import asyncio
import datetime
import json
import logging
import uuid
from urllib.parse import urlparse

import vertexai
from google.adk.artifacts import InMemoryArtifactService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from agents.scam_detector import scam_detector_agent
from config import LOCATION, PROJECT_ID
from db.operations import find_similar_patterns, save_case, save_fraud_pattern

try:
    from agents.audio_analyzer import audio_analyzer_agent  # type: ignore
except Exception:
    audio_analyzer_agent = None

try:
    from agents.apk_analyzer import apk_analyzer_agent  # type: ignore
except Exception:
    apk_analyzer_agent = None

try:
    from agents.golden_hour import golden_hour_agent  # type: ignore
except Exception:
    golden_hour_agent = None

try:
    from agents.osint import osint_agent  # type: ignore
except Exception:
    osint_agent = None

logger = logging.getLogger(__name__)

vertexai.init(project=PROJECT_ID, location=LOCATION)

session_service = InMemorySessionService()
artifact_service = InMemoryArtifactService()

APP_NAME = "satark_ai"
USER_ID = "satark_user"
A2A_PROTOCOL = "SATARK-A2A/1.0"

DEFAULT_PRIORITY_ACTIONS = [
    "Call 1930 immediately",
    "Do NOT share OTP or PIN",
    "File complaint at cybercrime.gov.in",
]


def generate_ack_id() -> str:
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:8].upper()
    return f"SATARK-{date_str}-{suffix}"


async def run_pipeline(input_type: str, payload: dict) -> dict:
    """Run detection, then OSINT and response planning in parallel with A2A handoffs."""
    ack_id = generate_ack_id()
    timestamp = datetime.datetime.now().isoformat()

    pipeline_stages: list[str] = []
    a2a_handoffs: list[dict] = []
    result = {
        "acknowledgment_id": ack_id,
        "case_id": ack_id,
        "input_type": input_type,
        "timestamp": timestamp,
        "pipeline_stages": pipeline_stages,
        "a2a_handoffs": a2a_handoffs,
        "is_scam": False,
        "risk_level": "UNKNOWN",
        "scam_type": "UNKNOWN",
        "confidence": 0,
        "red_flags": [],
        "extracted_entities": {},
        "victim_advice": "Call 1930 if you suspect fraud.",
        "osint_summary": "",
        "threat_score": 0,
        "priority_actions": [],
        "fir_template": "",
        "golden_hour_active": False,
        "calendar_event": {
            "attempted": False,
            "created": False,
            "title": "",
            "event_id": "",
            "start_time": "",
            "description": "",
            "error": "",
        },
        "similar_cases_found": 0,
    }

    try:
        primary_agent = _select_detection_agent(input_type)
        detection_handoff = _create_a2a_handoff(
            ack_id=ack_id,
            from_agent="satark_manager",
            to_agent=primary_agent.name,
            task="detect_and_classify",
            payload={"input_type": input_type},
        )
        a2a_handoffs.append(detection_handoff)

        detection = await _run_single_agent(
            agent=primary_agent,
            prompt=_build_detection_prompt(input_type, payload),
            ack_id=ack_id,
            handoff=detection_handoff,
        )
        for key, value in detection.items():
            if value is not None:
                result[key] = value

        result["extracted_entities"] = _normalize_entities(result.get("extracted_entities", {}))
        detection_handoff["status"] = "completed"
        pipeline_stages.append("detection")
    except Exception as e:
        logger.error(f"Stage 1 detection failed: {e}")
        pipeline_stages.append("detection_failed")
        result["error"] = str(e)

    # Enrich with pattern intelligence regardless of scam decision.
    text_for_similarity = payload.get("text", "")
    if isinstance(text_for_similarity, str) and text_for_similarity.strip():
        similar = find_similar_patterns(
            query_text=text_for_similarity,
            scam_type=result.get("scam_type"),
            limit=5,
        )
        result["similar_cases_found"] = len(similar)
        if similar:
            result["pattern_matches"] = [
                {
                    "scam_type": item.get("scam_type", "UNKNOWN"),
                    "sub_type": item.get("sub_type", ""),
                    "score": item.get("score", 0),
                }
                for item in similar
            ]

    indicators = _collect_indicators(result.get("extracted_entities", {}))
    can_run_osint = (
        osint_agent is not None
        and result.get("is_scam")
        and _safe_int(result.get("confidence"), 0) > 30
        and len(indicators) > 0
    )

    parallel_tasks: dict[str, asyncio.Task] = {}

    if can_run_osint:
        osint_handoff = _create_a2a_handoff(
            ack_id=ack_id,
            from_agent="satark_manager",
            to_agent=osint_agent.name,
            task="investigate_indicators",
            payload={"indicators": indicators},
        )
        a2a_handoffs.append(osint_handoff)
        parallel_tasks["osint"] = asyncio.create_task(
            _run_single_agent(
                agent=osint_agent,
                prompt=_build_osint_prompt(indicators),
                ack_id=ack_id,
                handoff=osint_handoff,
            )
        )

    if golden_hour_agent is not None:
        golden_handoff = _create_a2a_handoff(
            ack_id=ack_id,
            from_agent="satark_manager",
            to_agent=golden_hour_agent.name,
            task="generate_golden_hour_plan",
            payload={
                "scam_type": result.get("scam_type"),
                "risk_level": result.get("risk_level"),
            },
        )
        a2a_handoffs.append(golden_handoff)
        parallel_tasks["golden_hour"] = asyncio.create_task(
            _run_single_agent(
                agent=golden_hour_agent,
                prompt=_build_golden_hour_prompt(result),
                ack_id=ack_id,
                handoff=golden_handoff,
            )
        )

    if parallel_tasks:
        task_keys = list(parallel_tasks.keys())
        task_results = await asyncio.gather(*parallel_tasks.values(), return_exceptions=True)

        for key, output in zip(task_keys, task_results):
            if isinstance(output, Exception):
                logger.error(f"Parallel stage {key} failed: {output}")
                pipeline_stages.append(f"{key}_failed")
                if key == "golden_hour":
                    result["priority_actions"] = DEFAULT_PRIORITY_ACTIONS
                continue

            if key == "osint":
                result["osint_summary"] = output.get("osint_summary", "")
                result["threat_score"] = _safe_int(output.get("threat_score"), 0)
                extra_flags = output.get("red_flags") or []
                if isinstance(extra_flags, list):
                    result["red_flags"] = list(dict.fromkeys((result.get("red_flags") or []) + extra_flags))
                pipeline_stages.append("osint")
            elif key == "golden_hour":
                result["priority_actions"] = output.get("priority_actions", [])
                result["fir_template"] = output.get("fir_template", "")
                result["golden_hour_active"] = bool(output.get("golden_hour_active", False))
                calendar_event = output.get("calendar_event")
                if isinstance(calendar_event, dict):
                    result["calendar_event"] = {
                        "attempted": bool(calendar_event.get("attempted", False)),
                        "created": bool(calendar_event.get("created", False)),
                        "title": str(calendar_event.get("title", "")),
                        "event_id": str(calendar_event.get("event_id", "")),
                        "start_time": str(calendar_event.get("start_time", "")),
                        "description": str(calendar_event.get("description", "")),
                        "error": str(calendar_event.get("error", "")),
                    }
                pipeline_stages.append("golden_hour")

    if not result.get("priority_actions"):
        result["priority_actions"] = DEFAULT_PRIORITY_ACTIONS
        if "golden_hour" not in pipeline_stages and "golden_hour_failed" not in pipeline_stages:
            pipeline_stages.append("golden_hour_fallback")

    result["pipeline_stages"] = pipeline_stages
    _persist_to_db(result, payload.get("text", ""))
    return result


async def _run_single_agent(agent, prompt: str, ack_id: str, handoff: dict | None = None) -> dict:
    """Run one agent with a per-agent session and parse final JSON text parts."""
    if agent is None:
        raise ValueError("agent is None")

    session_id = f"{ack_id}-{agent.name}-{uuid.uuid4().hex[:6]}"
    await session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=session_id)

    local_runner = Runner(
        agent=agent,
        app_name=APP_NAME,
        session_service=session_service,
        artifact_service=artifact_service,
    )

    full_prompt = _wrap_prompt_with_a2a(prompt, handoff)
    text_parts: list[str] = []
    async for event in local_runner.run_async(
        user_id=USER_ID,
        session_id=session_id,
        new_message=genai_types.Content(
            role="user",
            parts=[genai_types.Part(text=full_prompt)],
        ),
    ):
        if event.is_final_response() and event.content:
            for part in event.content.parts:
                if part.text:
                    text_parts.append(part.text)

    raw = "\n".join([p for p in text_parts if p]).strip()
    parsed = _parse_agent_response(raw if raw else None)
    if handoff is not None:
        handoff["status"] = "completed"
    return parsed


def _wrap_prompt_with_a2a(prompt: str, handoff: dict | None) -> str:
    if not handoff:
        return prompt
    envelope = json.dumps(handoff, ensure_ascii=True)
    return (
        "A2A handoff envelope (metadata only):\n"
        f"{envelope}\n\n"
        "Task:\n"
        f"{prompt}"
    )


def _create_a2a_handoff(
    ack_id: str,
    from_agent: str,
    to_agent: str,
    task: str,
    payload: dict,
) -> dict:
    return {
        "protocol": A2A_PROTOCOL,
        "acknowledgment_id": ack_id,
        "message_id": uuid.uuid4().hex,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "from": from_agent,
        "to": to_agent,
        "task": task,
        "payload": payload,
        "status": "dispatched",
    }


def _parse_agent_response(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        clean = raw.strip()
        if "```" in clean:
            chunks = [c.strip() for c in clean.split("```") if c.strip()]
            for chunk in chunks:
                if chunk.startswith("json"):
                    chunk = chunk[4:].strip()
                try:
                    return json.loads(chunk)
                except Exception:
                    continue

        start = clean.find("{")
        end = clean.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(clean[start : end + 1])

        return json.loads(clean)
    except Exception:
        return {}


def _build_detection_prompt(input_type: str, payload: dict) -> str:
    if input_type == "text":
        return (
            "Analyze this for fraud and return strict JSON only.\n\n"
            f"{payload.get('text', '')}"
        )
    if input_type == "image":
        return "Analyze this screenshot for fraud signs and return strict JSON only."
    if input_type == "audio":
        return "Analyze this audio for vishing patterns and return strict JSON only."
    if input_type == "apk":
        return (
            "Analyze APK static results and return strict JSON only.\n"
            f"{json.dumps(payload.get('static_results', {}))}"
        )
    return "Analyze for fraud and return strict JSON only."


def _select_detection_agent(input_type: str):
    if input_type == "audio" and audio_analyzer_agent is not None:
        return audio_analyzer_agent
    if input_type == "apk" and apk_analyzer_agent is not None:
        return apk_analyzer_agent
    return scam_detector_agent


def _build_osint_prompt(indicators: list[str]) -> str:
    return (
        "Investigate these suspicious indicators and return strict JSON only.\n"
        f"Indicators: {indicators}"
    )


def _build_golden_hour_prompt(result: dict) -> str:
    return (
        "Generate a Golden Hour response plan for this fraud case and return strict JSON only.\n"
        f"Case ID: {result.get('case_id')}\n"
        f"Scam Type: {result.get('scam_type')}\n"
        f"Risk Level: {result.get('risk_level')}\n"
        f"Confidence: {result.get('confidence')}\n"
        f"Red Flags: {result.get('red_flags')}\n"
        "If golden_hour_active is true, create a Google Calendar event titled "
        "'FILE CYBERCRIME COMPLAINT — SATARK [case_id]' with a 30-minute reminder "
        "and include https://cybercrime.gov.in in the event description."
    )


def _normalize_entities(entities: dict) -> dict:
    if not isinstance(entities, dict):
        return {"urls": [], "phones": [], "domains": [], "upi_ids": [], "account_numbers": []}

    urls = _as_list(entities.get("urls") or entities.get("url") or entities.get("links"))
    phones = _as_list(entities.get("phones") or entities.get("phone_numbers"))
    domains = _as_list(entities.get("domains"))
    upi_ids = _as_list(entities.get("upi_ids"))
    account_numbers = _as_list(entities.get("account_numbers"))

    for url in urls:
        domain = _extract_domain(url)
        if domain:
            domains.append(domain)

    return {
        "urls": list(dict.fromkeys(urls)),
        "phones": list(dict.fromkeys(phones)),
        "domains": list(dict.fromkeys(domains)),
        "upi_ids": list(dict.fromkeys(upi_ids)),
        "account_numbers": list(dict.fromkeys(account_numbers)),
    }


def _collect_indicators(entities: dict) -> list[str]:
    if not isinstance(entities, dict):
        return []
    urls = _as_list(entities.get("urls"))
    phones = _as_list(entities.get("phones"))
    domains = _as_list(entities.get("domains"))
    return list(dict.fromkeys(urls + phones + domains))


def _extract_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"http://{value}")
    domain = parsed.netloc or parsed.path.split("/")[0]
    return domain.lower().strip()


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def _persist_to_db(result: dict, original_text: str):
    try:
        save_case(result["acknowledgment_id"], result)
        if result.get("is_scam") and original_text:
            save_fraud_pattern(
                text=original_text,
                scam_type=result.get("scam_type", "UNKNOWN"),
                confidence=result.get("confidence", 0),
            )
    except Exception as e:
        logger.error(f"DB persist failed: {e}")
