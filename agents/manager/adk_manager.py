import asyncio
import base64
import datetime
import inspect
import json
import logging
import os
import re
import uuid
from urllib.parse import urlparse

import vertexai
from google import genai
from google.adk.artifacts import InMemoryArtifactService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from agents.scam_detector import scam_detector_agent
from config import LOCATION, MODEL_FLASH, PROJECT_ID
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
    from agents.golden_hour import build_golden_hour_agent  # type: ignore
except Exception:
    build_golden_hour_agent = None

try:
    from agents.golden_hour.adk_agent import schedule_golden_hour_calendar_events  # type: ignore
except Exception:
    schedule_golden_hour_calendar_events = None  # type: ignore

from db.sessions_repo import get_google_oauth

from tools.google_workspace import (
    build_google_credentials,
    create_case_report_doc,
    create_gmail_draft,
    create_golden_hour_tasks,
)

try:
    from agents.osint import osint_agent  # type: ignore
except Exception:
    osint_agent = None

logger = logging.getLogger(__name__)

vertexai.init(project=PROJECT_ID, location=LOCATION)

genai_client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)

session_service = InMemorySessionService()
artifact_service = InMemoryArtifactService()

APP_NAME = "satark_ai"
USER_ID = "satark_user"
A2A_PROTOCOL = "SATARK-A2A/1.0"

DEFAULT_PRIORITY_ACTIONS = [
    "Review the manager response and follow the recommended actions.",
    "Preserve the suspicious message or file as evidence.",
    "Escalate only if reporting or emergency is explicitly recommended.",
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
        "victim_advice": "Review the manager guidance and follow recommended actions.",
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
        "google_tasks": {
            "attempted": False,
            "created": False,
            "tasklist_id": "",
            "tasks_created": 0,
            "task_ids": [],
            "task_url": "",
            "error": "",
        },
        "case_report_doc": {
            "attempted": False,
            "created": False,
            "doc_id": "",
            "doc_url": "",
            "error": "",
        },
        "gmail_draft": {
            "attempted": False,
            "created": False,
            "draft_id": "",
            "draft_url": "",
            "error": "",
        },
        "similar_cases_found": 0,
    }

    recovery_answers = _normalize_recovery_answers(payload if isinstance(payload, dict) else {})
    result["recovery_answers"] = recovery_answers

    try:
        primary_agent = _select_detection_agent(input_type)
        attachments: list[genai_types.Part] = []
        if input_type == "image":
            try:
                image_b64 = payload.get("image_b64")
                mime_type = str(payload.get("mime_type") or "image/jpeg")
                if isinstance(image_b64, str) and image_b64.strip():
                    raw = base64.b64decode(image_b64)
                    attachments = [genai_types.Part.from_bytes(data=raw, mime_type=mime_type)]
            except Exception:
                attachments = []

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
            attachments=attachments,
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
    can_run_osint = osint_agent is not None and len(indicators) > 0

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

    google_oauth = None
    session_id = None
    if isinstance(payload, dict):
        session_id = str(payload.get("session_id") or "") or None
        google_oauth = get_google_oauth(session_id or "")

    golden_hour_agent = None
    if build_golden_hour_agent is not None:
        try:
            golden_hour_agent = build_golden_hour_agent(google_oauth=google_oauth, session_id=session_id)
        except Exception:
            golden_hour_agent = build_golden_hour_agent()  # type: ignore

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
                prompt=_build_golden_hour_prompt(result, str(payload.get("text") or "")),
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
                # Keep the full OSINT payload for downstream report rendering.
                result["osint"] = output
                result["osint_summary"] = str(output.get("osint_summary") or output.get("threat_summary") or "")
                result["threat_score"] = _safe_int(output.get("threat_score") or output.get("overall_threat_score"), 0)
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
                    if bool(result["calendar_event"].get("created")):
                        logger.info(
                            "golden_hour.calendar_event created event_id=%s start_time=%s",
                            result["calendar_event"].get("event_id"),
                            result["calendar_event"].get("start_time"),
                        )
                pipeline_stages.append("golden_hour")

    # Ensure the pipeline always carries a usable FIR/NCRP-ready body even if
    # the Golden Hour agent returns an empty or too-short template.
    fir_value = result.get("fir_template")
    fir_text = ""
    if isinstance(fir_value, dict):
        fir_text = str(fir_value.get("case_summary") or fir_value.get("text") or "")
    else:
        fir_text = str(fir_value or "")
    if len(fir_text.strip()) < 200:
        result["fir_template"] = _build_fir_template_fallback(
            case_id=str(result.get("case_id") or ack_id),
            scam_type=str(result.get("scam_type") or "Cyber Fraud"),
            risk_level=str(result.get("risk_level") or "HIGH"),
            victim_text=str(payload.get("text") or "").strip(),
            entities=result.get("extracted_entities") if isinstance(result.get("extracted_entities"), dict) else {},
            red_flags=result.get("red_flags") if isinstance(result.get("red_flags"), list) else [],
            victim_advice=str(result.get("victim_advice") or "").strip(),
        )

    if not result.get("priority_actions"):
        result["priority_actions"] = DEFAULT_PRIORITY_ACTIONS
        if "golden_hour" not in pipeline_stages and "golden_hour_failed" not in pipeline_stages:
            pipeline_stages.append("golden_hour_fallback")

    # Final manager decision contract (AI-generated): route, verdict, evidence,
    # action steps, reporting decision, and MCP plan.
    decision_contract = await _generate_manager_decision_contract(
        input_type=input_type,
        payload=payload if isinstance(payload, dict) else {},
        base_result=result,
        recovery_answers=recovery_answers,
    )
    result.update(decision_contract)
    if isinstance(result.get("action_steps"), list) and result.get("action_steps"):
        result["priority_actions"] = list(result.get("action_steps") or [])

    # Deterministic MCP execution based on manager decision contract.
    trigger_mcp_actions = bool(result.get("requires_mcp", False))
    mcp_plan = _normalize_mcp_plan(
        requires_mcp=trigger_mcp_actions,
        raw_plan=result.get("mcp_plan") if isinstance(result.get("mcp_plan"), dict) else None,
        requires_reporting=bool(result.get("requires_reporting", False)),
    )
    result["mcp_plan"] = mcp_plan
    create_calendar = bool(mcp_plan.get("create_calendar"))
    create_tasks = bool(mcp_plan.get("create_tasks"))
    create_gmail_draft = bool(mcp_plan.get("create_gmail_draft"))
    create_case_report_doc = bool(mcp_plan.get("create_case_report_doc"))

    has_oauth_tokens = False
    if isinstance(google_oauth, dict):
        has_oauth_tokens = bool(
            google_oauth.get("calendar_mcp_token_path")
            or google_oauth.get("refresh_token")
            or google_oauth.get("access_token")
        )

    should_trigger_workspace_actions = trigger_mcp_actions and has_oauth_tokens

    should_schedule_calendar = (
        should_trigger_workspace_actions
        and create_calendar
        and schedule_golden_hour_calendar_events is not None
    )

    creds = None
    if trigger_mcp_actions and has_oauth_tokens and isinstance(google_oauth, dict):
        try:
            creds = build_google_credentials(google_oauth)
        except Exception:
            if should_schedule_calendar:
                try:
                    calendar_event = await schedule_golden_hour_calendar_events(
                        google_oauth=google_oauth,
                        session_id=session_id,
                        case_id=str(result.get("case_id") or ack_id),
                        scam_type=str(result.get("scam_type") or "Cyber Fraud"),
                        minutes_elapsed=payload.get("minutes_since_fraud"),
                    )
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
                        if bool(result["calendar_event"].get("created")):
                            logger.info(
                                "golden_hour.calendar_event scheduled event_id=%s start_time=%s",
                                result["calendar_event"].get("event_id"),
                                result["calendar_event"].get("start_time"),
                            )
                    pipeline_stages.append("calendar_scheduled")
                except Exception as e:
                    result["calendar_event"] = {
                        "attempted": True,
                        "created": False,
                        "title": str(result["calendar_event"].get("title", "")) if isinstance(result.get("calendar_event"), dict) else "",
                        "event_id": "",
                        "start_time": "",
                        "description": str(result["calendar_event"].get("description", "")) if isinstance(result.get("calendar_event"), dict) else "",
                        "error": str(e),
                    }
                    pipeline_stages.append("calendar_failed")

            # Google Tasks checklist (best-effort, manager-directed).
            if should_trigger_workspace_actions and create_tasks:
                if creds is None:
                    result["google_tasks"] = {
                        "attempted": False,
                        "created": False,
                        "tasklist_id": "",
                        "tasks_created": 0,
                        "task_ids": [],
                        "task_url": "",
                        "error": "google_oauth_not_connected" if not has_oauth_tokens else "credentials_unavailable",
                    }
                else:
                    try:
                        tasks_result = await asyncio.to_thread(
                            create_golden_hour_tasks,
                            creds,
                            case_id=str(result.get("case_id") or ack_id),
                            scam_type=str(result.get("scam_type") or "Cyber Fraud"),
                            complaint_text=result.get("fir_template") or "",
                        )
                        if isinstance(tasks_result, dict):
                            result["google_tasks"] = tasks_result
                        pipeline_stages.append(
                            "tasks_created" if isinstance(tasks_result, dict) and bool(tasks_result.get("created")) else "tasks_attempted"
                        )
                    except Exception as e:
                        result["google_tasks"] = {
                            "attempted": True,
                            "created": False,
                            "tasklist_id": "",
                            "tasks_created": 0,
                            "task_ids": [],
                            "task_url": "",
                            "error": str(e),
                        }
                        pipeline_stages.append("tasks_failed")
            elif trigger_mcp_actions and not create_tasks:
                result["google_tasks"] = {
                    "attempted": False,
                    "created": False,
                    "tasklist_id": "",
                    "tasks_created": 0,
                    "task_ids": [],
                    "task_url": "",
                    "error": "not_requested",
                }

    # If the caller asked us to trigger MCP actions but we didn't schedule a calendar
    # event, keep evidence explicitly unattempted (the LLM output is not authoritative).
    if trigger_mcp_actions and create_calendar and not should_schedule_calendar:
        if not should_trigger_workspace_actions:
            calendar_error = "not_applicable"
        elif not has_oauth_tokens:
            calendar_error = "google_oauth_not_connected"
        else:
            calendar_error = "calendar_scheduler_unavailable"
        result["calendar_event"] = {
            "attempted": False,
            "created": False,
            "title": str(result["calendar_event"].get("title", "")) if isinstance(result.get("calendar_event"), dict) else "",
            "event_id": "",
            "start_time": "",
            "description": str(result["calendar_event"].get("description", "")) if isinstance(result.get("calendar_event"), dict) else "",
            "error": calendar_error,
        }
    elif trigger_mcp_actions and not create_calendar:
        result["calendar_event"] = {
            "attempted": False,
            "created": False,
            "title": "",
            "event_id": "",
            "start_time": "",
            "description": "",
            "error": "not_requested",
        }

    # Google Docs and Gmail drafts (best-effort; manager-directed).
    if trigger_mcp_actions and not should_trigger_workspace_actions:
        result["case_report_doc"] = {
            "attempted": False,
            "created": False,
            "doc_id": "",
            "doc_url": "",
            "error": "not_applicable",
        }
        result["gmail_draft"] = {
            "attempted": False,
            "created": False,
            "draft_id": "",
            "draft_url": "",
            "error": "not_applicable",
        }

    if trigger_mcp_actions and should_trigger_workspace_actions and not create_case_report_doc:
        result["case_report_doc"] = {
            "attempted": False,
            "created": False,
            "doc_id": "",
            "doc_url": "",
            "error": "not_requested",
        }

    if trigger_mcp_actions and should_trigger_workspace_actions and not create_gmail_draft:
        result["gmail_draft"] = {
            "attempted": False,
            "created": False,
            "draft_id": "",
            "draft_url": "",
            "error": "not_requested",
        }

    if should_trigger_workspace_actions:
        if creds is None:
            if create_case_report_doc:
                result["case_report_doc"] = {
                    "attempted": False,
                    "created": False,
                    "doc_id": "",
                    "doc_url": "",
                    "error": "google_oauth_not_connected" if not has_oauth_tokens else "credentials_unavailable",
                }
            if create_gmail_draft:
                result["gmail_draft"] = {
                    "attempted": False,
                    "created": False,
                    "draft_id": "",
                    "draft_url": "",
                    "error": "google_oauth_not_connected" if not has_oauth_tokens else "credentials_unavailable",
                }
        else:
            try:
                case_id = str(result.get("case_id") or ack_id)
                generated = (
                    datetime.datetime.now(datetime.timezone.utc)
                    .astimezone()
                    .replace(microsecond=0)
                    .isoformat(timespec="seconds")
                )
                verdict = f"{str(result.get('risk_level') or '').strip()} — {str(result.get('scam_type') or '').strip()}"
                confidence = result.get("confidence")
                summary = str(result.get("summary") or result.get("victim_advice") or "").strip()
                red_flags = result.get("red_flags") if isinstance(result.get("red_flags"), list) else []
                osint_summary = str(result.get("osint_summary") or "").strip()
                fir = str(result.get("fir_template") or "").strip()

                flags_text = "\n".join([f"• {str(x).strip()}" for x in red_flags if str(x).strip()]) or "• (none)"
                action_steps = [str(x).strip() for x in (result.get("action_steps") or result.get("priority_actions") or []) if str(x).strip()]
                actions_text = "\n".join([f"{idx + 1}. {step}" for idx, step in enumerate(action_steps)]) or "1. (not available)"
                report_text = (
                    "SATARK AI — Investigation Report\n"
                    f"Case ID: {case_id}\n"
                    f"Generated: {generated}\n\n"
                    f"VERDICT: {verdict} (confidence: {confidence})\n\n"
                    "WHAT HAPPENED\n"
                    f"{summary or '(not available)'}\n\n"
                    "SIGNALS DETECTED\n"
                    f"{flags_text}\n\n"
                    "OSINT FINDINGS\n"
                    f"{osint_summary or '(not available)'}\n\n"
                    "IMMEDIATE ACTIONS\n"
                    f"{actions_text}\n\n"
                    "PRE-FILLED COMPLAINT (copy to NCRP)\n"
                    f"{fir or '(not available)'}\n\n"
                    f"ACKNOWLEDGMENT ID: {case_id}\n"
                )

                if create_case_report_doc:
                    doc_result = await asyncio.to_thread(
                        create_case_report_doc,
                        creds,
                        case_id=case_id,
                        title=f"SATARK Report — {case_id}",
                        report_text=report_text,
                    )
                    if isinstance(doc_result, dict):
                        result["case_report_doc"] = doc_result
                    pipeline_stages.append(
                        "doc_created" if isinstance(doc_result, dict) and bool(doc_result.get("created")) else "doc_attempted"
                    )

                gmail_body = (
                    "Hello,\n\n"
                    "I am reporting a suspected cyber fraud incident.\n\n"
                    f"Case ID: {case_id}\n"
                    f"Scam Type: {str(result.get('scam_type') or 'UNKNOWN')}\n"
                    f"Risk Level: {str(result.get('risk_level') or 'UNKNOWN')}\n\n"
                    "Summary:\n"
                    f"{summary or '(not available)'}\n\n"
                    "I request immediate assistance and acknowledgement.\n"
                )
                if create_gmail_draft:
                    gmail_result = await asyncio.to_thread(
                        create_gmail_draft,
                        creds,
                        to_email="complaints@cybercrime.gov.in",
                        subject=f"SATARK Incident Report — {case_id}",
                        body_text=gmail_body,
                    )
                    if isinstance(gmail_result, dict):
                        result["gmail_draft"] = gmail_result
                    pipeline_stages.append(
                        "gmail_draft_created" if isinstance(gmail_result, dict) and bool(gmail_result.get("created")) else "gmail_draft_attempted"
                    )
            except Exception as e:
                result["case_report_doc"] = {
                    "attempted": True,
                    "created": False,
                    "doc_id": "",
                    "doc_url": "",
                    "error": str(e),
                }
                pipeline_stages.append("doc_failed")
                result["gmail_draft"] = {
                    "attempted": True,
                    "created": False,
                    "draft_id": "",
                    "draft_url": "",
                    "error": str(e),
                }
                pipeline_stages.append("gmail_draft_failed")

    result["pipeline_stages"] = pipeline_stages
    _persist_to_db(result, payload.get("text", ""))
    return result


async def _run_single_agent(
    agent,
    prompt: str,
    ack_id: str,
    handoff: dict | None = None,
    attachments: list[genai_types.Part] | None = None,
) -> dict:
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

    timeout_s = 0.0
    try:
        timeout_s = float(os.getenv("SATARK_ADK_AGENT_TIMEOUT_S", "60"))
    except Exception:
        timeout_s = 60.0

    try:
        # Gemini 3 preview can emit tool-only turns (`function_call` parts). Some
        # ADK model adapters end up calling the GenAI response `.text` accessor,
        # which strips non-text parts and can deadlock tool flows. For agents
        # whose tools are *pure* Python FunctionTools, we bypass Runner and run a
        # function-call aware loop directly against google.genai.
        if _agent_uses_only_function_tools(agent):
            parsed = await _run_function_tool_agent_direct(
                agent=agent,
                prompt=full_prompt,
                timeout_s=timeout_s,
                first_turn_parts=attachments,
            )
            if handoff is not None:
                handoff["status"] = "completed"
            return parsed

        if timeout_s and timeout_s > 0:
            async with asyncio.timeout(timeout_s):
                parts = []
                if attachments:
                    parts.extend(attachments)
                parts.append(genai_types.Part(text=full_prompt))

                async for event in local_runner.run_async(
                    user_id=USER_ID,
                    session_id=session_id,
                    new_message=genai_types.Content(
                        role="user",
                        parts=parts,
                    ),
                ):
                    if event.is_final_response() and event.content:
                        for part in event.content.parts:
                            if part.text:
                                text_parts.append(part.text)
        else:
            parts = []
            if attachments:
                parts.extend(attachments)
            parts.append(genai_types.Part(text=full_prompt))

            async for event in local_runner.run_async(
                user_id=USER_ID,
                session_id=session_id,
                new_message=genai_types.Content(
                    role="user",
                    parts=parts,
                ),
            ):
                if event.is_final_response() and event.content:
                    for part in event.content.parts:
                        if part.text:
                            text_parts.append(part.text)
    except TimeoutError as exc:
        if handoff is not None:
            handoff["status"] = "timeout"
        raise TimeoutError(f"agent_timeout:{getattr(agent, 'name', 'unknown')}") from exc

    raw = "\n".join([p for p in text_parts if p]).strip()
    parsed = _parse_agent_response(raw if raw else None)
    if handoff is not None:
        handoff["status"] = "completed"
    return parsed


def _agent_uses_only_function_tools(agent) -> bool:
    tools = getattr(agent, "tools", None)
    if not tools:
        return False
    for tool in tools:
        func = getattr(tool, "func", None)
        if not callable(func):
            return False
        name = getattr(tool, "name", None)
        if not isinstance(name, str) or not name.strip():
            return False
    return True


def _schema_for_python_type(annotation) -> genai_types.Schema:
    # Best-effort mapping; default to STRING for robustness.
    if annotation is str:
        return genai_types.Schema(type="STRING")
    if annotation is int:
        return genai_types.Schema(type="INTEGER")
    if annotation is float:
        return genai_types.Schema(type="NUMBER")
    if annotation is bool:
        return genai_types.Schema(type="BOOLEAN")
    if annotation is dict or getattr(annotation, "__origin__", None) is dict:
        return genai_types.Schema(type="OBJECT")
    if annotation is list or getattr(annotation, "__origin__", None) is list:
        return genai_types.Schema(type="ARRAY", items=genai_types.Schema(type="STRING"))
    return genai_types.Schema(type="STRING")


def _build_function_declarations(tools: list) -> tuple[list[genai_types.FunctionDeclaration], dict[str, callable]]:
    declarations: list[genai_types.FunctionDeclaration] = []
    registry: dict[str, callable] = {}

    for tool in tools:
        func = getattr(tool, "func", None)
        name = str(getattr(tool, "name", "") or "").strip()
        if not name or not callable(func):
            continue

        description = str(getattr(tool, "description", "") or "").strip() or None
        sig = inspect.signature(func)
        properties: dict[str, genai_types.Schema] = {}
        required: list[str] = []
        for param_name, param in sig.parameters.items():
            if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            annotation = param.annotation
            if annotation is inspect._empty:
                annotation = str
            properties[param_name] = _schema_for_python_type(annotation)
            if param.default is inspect._empty:
                required.append(param_name)

        declarations.append(
            genai_types.FunctionDeclaration(
                name=name,
                description=description,
                parameters=genai_types.Schema(
                    type="OBJECT",
                    properties=properties or {},
                    required=required or None,
                ),
            )
        )
        registry[name] = func

    return declarations, registry


def _contains_url(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"https?://\S+", text))


def _maybe_builtin_tools_for_agent(agent, prompt: str) -> list[genai_types.Tool]:
    name = str(getattr(agent, "name", "") or "").strip().lower()
    if name not in {"osint_agent", "osint"}:
        return []

    enabled = str(os.getenv("SATARK_ENABLE_OSINT_GROUNDING", "1") or "1").strip().lower() not in {"0", "false", "no"}
    if not enabled:
        return []

    tools: list[genai_types.Tool] = []
    try:
        google_search_cls = getattr(genai_types, "GoogleSearch", None)
        if google_search_cls is not None:
            tools.append(genai_types.Tool(google_search=google_search_cls()))
    except Exception:
        pass

    try:
        url_context_cls = getattr(genai_types, "UrlContext", None)
        if url_context_cls is not None and _contains_url(prompt):
            tools.append(genai_types.Tool(url_context=url_context_cls()))
    except Exception:
        pass

    return tools


async def _run_function_tool_agent_direct(
    agent,
    prompt: str,
    timeout_s: float,
    first_turn_parts: list[genai_types.Part] | None = None,
) -> dict:
    tools = list(getattr(agent, "tools", []) or [])
    declarations, registry = _build_function_declarations(tools)

    builtin_tools = _maybe_builtin_tools_for_agent(agent, prompt)

    all_tools: list[genai_types.Tool] | None = None
    if declarations or builtin_tools:
        all_tools = []
        if declarations:
            all_tools.append(genai_types.Tool(function_declarations=declarations))
        all_tools.extend(builtin_tools)

    config = genai_types.GenerateContentConfig(
        system_instruction=str(getattr(agent, "instruction", "") or ""),
        temperature=0.1,
        thinking_config=genai_types.ThinkingConfig(thinking_level="MINIMAL"),
        tools=all_tools,
        tool_config=genai_types.ToolConfig(
            function_calling_config=genai_types.FunctionCallingConfig(
                mode="AUTO",
            )
        )
        if registry
        else genai_types.ToolConfig(
            function_calling_config=genai_types.FunctionCallingConfig(mode="NONE")
        ),
        response_mime_type="application/json",
    )

    first_parts: list[genai_types.Part] = []
    if first_turn_parts:
        first_parts.extend(first_turn_parts)
    first_parts.append(genai_types.Part(text=prompt))

    history: list[genai_types.Content] = [genai_types.Content(role="user", parts=first_parts)]

    async def _run_loop() -> dict:
        max_steps = 8
        for _ in range(max_steps):
            try:
                resp = genai_client.models.generate_content(
                    model=str(getattr(agent, "model", "") or ""),
                    contents=history,
                    config=config,
                )
            except Exception as exc:
                # Best-effort fallback: if Google Search / URL Context are not enabled
                # in this project, retry once without built-in tools.
                if builtin_tools:
                    fallback_tools: list[genai_types.Tool] | None = None
                    if declarations:
                        fallback_tools = [genai_types.Tool(function_declarations=declarations)]
                    fallback_config = genai_types.GenerateContentConfig(
                        system_instruction=str(getattr(agent, "instruction", "") or ""),
                        temperature=0.1,
                        thinking_config=genai_types.ThinkingConfig(thinking_level="MINIMAL"),
                        tools=fallback_tools,
                        tool_config=config.tool_config,
                        response_mime_type="application/json",
                    )
                    resp = genai_client.models.generate_content(
                        model=str(getattr(agent, "model", "") or ""),
                        contents=history,
                        config=fallback_config,
                    )
                    builtin_tools.clear()
                else:
                    raise

            candidates = getattr(resp, "candidates", None)
            content = None
            if candidates and getattr(candidates[0], "content", None):
                content = candidates[0].content
                history.append(content)

            if not content or not getattr(content, "parts", None):
                break

            function_calls: list[genai_types.FunctionCall] = []
            text_parts: list[str] = []

            for part in content.parts or []:
                fc = getattr(part, "function_call", None)
                if fc and getattr(fc, "name", None):
                    function_calls.append(fc)
                t = getattr(part, "text", None)
                if isinstance(t, str) and t:
                    text_parts.append(t)

            if not function_calls:
                raw = "\n".join([t for t in text_parts if t]).strip()
                return _parse_agent_response(raw if raw else None)

            tool_response_parts: list[genai_types.Part] = []
            for call in function_calls:
                name = str(getattr(call, "name", "") or "").strip()
                func = registry.get(name)
                args = getattr(call, "args", None)
                if not isinstance(args, dict):
                    args = {}

                response_payload: dict
                if not callable(func):
                    response_payload = {"error": f"unknown_function:{name}"}
                else:
                    try:
                        sig = inspect.signature(func)
                        filtered = {k: v for k, v in args.items() if k in sig.parameters}
                        response_payload = await asyncio.to_thread(func, **filtered)
                        if not isinstance(response_payload, dict):
                            response_payload = {"result": response_payload}
                    except Exception as e:
                        response_payload = {"error": str(e)}

                tool_response_parts.append(
                    genai_types.Part(
                        function_response=genai_types.FunctionResponse(
                            id=getattr(call, "id", None),
                            name=name,
                            response=response_payload,
                        )
                    )
                )

            # Vertex requires the tool response turn to include the same number
            # of function_response parts as the preceding function_call turn.
            history.append(genai_types.Content(role="tool", parts=tool_response_parts))

        return {}

    if timeout_s and timeout_s > 0:
        async with asyncio.timeout(timeout_s):
            return await _run_loop()
    return await _run_loop()


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
    recovery_answers = payload.get("recovery_answers") if isinstance(payload.get("recovery_answers"), dict) else {}
    user_context = payload.get("user_context") if isinstance(payload.get("user_context"), dict) else {}
    preprocessed_context = payload.get("preprocessed_context") if isinstance(payload.get("preprocessed_context"), dict) else {}
    context_block = (
        "\n\nUser intake context:\n"
        f"{json.dumps({'recovery_answers': recovery_answers, 'user_context': user_context, 'preprocessed_context': preprocessed_context}, ensure_ascii=True)}"
    )

    if input_type == "text":
        return (
            "Analyze this for fraud and return strict JSON only.\n\n"
            f"{payload.get('text', '')}"
            f"{context_block}"
        )
    if input_type == "image":
        return "Analyze this screenshot for fraud signs and return strict JSON only." + context_block
    if input_type == "audio":
        return "Analyze this audio for vishing patterns and return strict JSON only." + context_block
    if input_type == "apk":
        return (
            "Analyze APK static results and return strict JSON only.\n"
            f"{json.dumps(payload.get('static_results', {}))}"
            f"{context_block}"
        )
    return "Analyze for fraud and return strict JSON only." + context_block


def _select_detection_agent(input_type: str):
    if input_type == "audio" and audio_analyzer_agent is not None:
        return audio_analyzer_agent
    if input_type == "apk" and apk_analyzer_agent is not None:
        return apk_analyzer_agent
    return scam_detector_agent


def _build_osint_prompt(indicators: list[str]) -> str:
    return (
        "Investigate these indicators using OSINT tools and return STRICT JSON only (no prose, no markdown).\n"
        "\n"
        "Indicators:\n"
        f"{json.dumps(indicators)}\n"
        "\n"
        "Required JSON shape (fill as much as you can; use empty strings/arrays when unknown):\n"
        "{\n"
        '  "indicators_investigated": ["..."],\n'
        '  "domains": {\n'
        '    "example.com": {\n'
        '      "domain_age_days": 0,\n'
        '      "registrar": "",\n'
        '      "hosting_country": "",\n'
        '      "ssl": {"present": false, "issuer": "", "valid_to": ""}\n'
        "    }\n"
        "  },\n"
        '  "ips": {\n'
        '    "1.2.3.4": {\n'
        '      "reputation": "GOOD|UNKNOWN|SUSPICIOUS|MALICIOUS",\n'
        '      "asn_org": "",\n'
        '      "abuse_reports": 0\n'
        "    }\n"
        "  },\n"
        '  "urls": {"https://...": {"verdict": "SAFE|SUSPICIOUS|MALICIOUS", "red_flags": []}},\n'
        '  "threat_summary": "One paragraph summary grounded in findings",\n'
        '  "overall_threat_score": 0,\n'
        '  "red_flags": ["..."],\n'
        '  "recommendations": ["..."],\n'
        '  "sources": ["whois", "crtsh", "web_risk", "reverse_ip", "asn", "abuse_reports"]\n'
        "}\n"
    )
def _build_golden_hour_prompt(result: dict, victim_text: str) -> str:
    extracted = result.get("extracted_entities") if isinstance(result.get("extracted_entities"), dict) else {}
    return (
        "Generate a Golden Hour response plan for this fraud case and return strict JSON only.\n"
        "Only set golden_hour_active = true when there is concrete evidence of active compromise or ongoing financial risk.\n"
        "Do not activate solely due to category labels, confidence, or similarity counts.\n\n"
        f"Case ID: {result.get('case_id')}\n"
        f"Scam Type: {result.get('scam_type')}\n"
        f"Risk Level: {result.get('risk_level')}\n"
        f"Confidence: {result.get('confidence')}\n"
        f"Red Flags: {result.get('red_flags')}\n"
        f"Extracted Entities: {json.dumps(extracted, ensure_ascii=True)}\n\n"
        "Victim's message (verbatim):\n"
        f"{victim_text}\n\n"
        "Requirements:\n"
        "- Keep actions aligned to actual impact and urgency in this case.\n"
        "- fir_template MUST be a complete NCRP-ready body (>= 300 chars).\n"
        "- If golden_hour_active is true, create a Google Calendar event title aligned to the case plan and include relevant follow-up details.\n"
        "- Do not fabricate calendar event ids.\n"
    )


def _build_fir_template_fallback(
    *,
    case_id: str,
    scam_type: str,
    risk_level: str,
    victim_text: str,
    entities: dict,
    red_flags: list,
    victim_advice: str,
) -> str:
    def _as_list(value) -> list[str]:
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    urls = _as_list(entities.get("urls"))
    phones = _as_list(entities.get("phones") or entities.get("phone_numbers"))
    upi_ids = _as_list(entities.get("upi_ids"))
    account_numbers = _as_list(entities.get("account_numbers"))

    def _bullets(items: list[str]) -> str:
        return "\n".join([f"- {x}" for x in items]) if items else "- (not available)"

    summary = victim_advice or victim_text
    summary = (summary or "").strip()
    if summary and len(summary) > 1200:
        summary = summary[:1200].rstrip() + "…"

    flags = [str(x).strip() for x in (red_flags or []) if str(x).strip()]

    return (
        "CYBER CRIME COMPLAINT (NCRP DRAFT)\n"
        f"Acknowledgment/Case ID: {case_id}\n"
        "\n"
        "1) Complainant Details\n"
        "Name: [Your Name]\n"
        "Mobile: [Your Mobile Number]\n"
        "Email: [Your Email]\n"
        "Address: [Your Address]\n"
        "\n"
        "2) Incident Details\n"
        f"Category/Type: {scam_type}\n"
        f"Risk Level: {risk_level}\n"
        "Date & Time of Incident: [DD/MM/YYYY, HH:MM]\n"
        "Description of Incident:\n"
        f"{summary or '[Describe what happened in your own words]'}\n"
        "\n"
        "3) Red Flags Observed\n"
        f"{_bullets(flags)}\n"
        "\n"
        "4) Suspect / Accused Details (as available)\n"
        "Phone Numbers:\n"
        f"{_bullets(phones)}\n"
        "UPI IDs:\n"
        f"{_bullets(upi_ids)}\n"
        "Bank Account Numbers:\n"
        f"{_bullets(account_numbers)}\n"
        "Suspicious URLs / Links:\n"
        f"{_bullets(urls)}\n"
        "\n"
        "5) Immediate Actions Requested\n"
        "- I request immediate fund-protection / freeze action through the 1930 helpline.\n"
        "- I request registration of my complaint on cybercrime.gov.in and investigation of the above incident.\n"
        "\n"
        "6) Evidence Preserved\n"
        "- Call logs / caller number screenshots\n"
        "- SMS/WhatsApp screenshots\n"
        "- Bank transaction reference/UTR (if any)\n"
        "- Screenshots/recordings of any link/app used\n"
        "\n"
        "Place: [City]\n"
        "Date: [DD/MM/YYYY]\n"
        "Signature: [Your Name]\n"
    )


def _normalize_recovery_answers(payload: dict) -> dict[str, Any]:
    raw = payload.get("recovery_answers") if isinstance(payload, dict) else None
    if not isinstance(raw, dict):
        options = payload.get("options") if isinstance(payload, dict) else None
        if isinstance(options, dict):
            raw = options.get("recovery_answers") if isinstance(options.get("recovery_answers"), dict) else {}
        else:
            raw = {}

    provided = bool(raw)

    did_lose_money = bool(
        raw.get("did_lose_money")
        or raw.get("did_lose_money_or_share_bank_details")
    )
    clicked_link = bool(raw.get("clicked_link") or raw.get("opened_link"))
    shared_personal_details = bool(
        raw.get("shared_personal_details")
        or raw.get("shared_sensitive_details")
        or raw.get("shared_identity_details")
        or raw.get("shared_aadhaar")
        or raw.get("shared_pan")
    )
    shared_bank_details = bool(
        raw.get("shared_bank_details")
        or raw.get("shared_bank_or_otp")
        or raw.get("shared_otp")
        or raw.get("shared_password")
        or raw.get("shared_upi_pin")
        or raw.get("shared_cvv")
    )
    installed_apk = bool(raw.get("installed_apk") or raw.get("installed_app"))
    account_compromise = bool(
        raw.get("account_compromise")
        or raw.get("unauthorized_access")
        or raw.get("ongoing_attack")
    )
    explicit_report_request = bool(raw.get("explicit_report_request"))

    try:
        amount_lost = float(raw.get("amount_lost") or 0)
    except Exception:
        amount_lost = 0.0
    amount_lost = max(0.0, amount_lost)

    time_bucket_raw = str(raw.get("time_bucket") or "").strip().lower()
    time_bucket = time_bucket_raw if time_bucket_raw in {"minutes", "hours", "days"} else None

    return {
        "provided": provided,
        "did_lose_money": did_lose_money,
        "clicked_link": clicked_link,
        "shared_personal_details": shared_personal_details,
        "shared_bank_details": shared_bank_details,
        "installed_apk": installed_apk,
        "account_compromise": account_compromise,
        "amount_lost": amount_lost,
        "time_bucket": time_bucket,
        "explicit_report_request": explicit_report_request,
        "reactive_recovery": bool(
            did_lose_money
            or shared_bank_details
            or shared_personal_details
            or account_compromise
        ),
    }


def _is_generic_verdict(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    generic = {
        "analysis complete",
        "analysis completed",
        "review required",
        "needs review",
        "result ready",
    }
    return text in generic


def _is_preventive_only_case(recovery_answers: dict[str, Any]) -> bool:
    if not isinstance(recovery_answers, dict) or not recovery_answers.get("provided"):
        return False
    return not any(
        [
            bool(recovery_answers.get("did_lose_money")),
            bool(recovery_answers.get("clicked_link")),
            bool(recovery_answers.get("shared_personal_details")),
            bool(recovery_answers.get("shared_bank_details")),
            bool(recovery_answers.get("installed_apk")),
            bool(recovery_answers.get("account_compromise")),
        ]
    )


def _normalize_mcp_plan(requires_mcp: bool, raw_plan: dict[str, Any] | None, requires_reporting: bool) -> dict[str, bool]:
    if not requires_mcp:
        return {
            "create_calendar": False,
            "create_tasks": False,
            "create_gmail_draft": False,
            "create_case_report_doc": False,
        }

    plan = raw_plan if isinstance(raw_plan, dict) else {}
    defaults = {
        "create_calendar": True,
        "create_tasks": True,
        "create_gmail_draft": bool(requires_reporting),
        "create_case_report_doc": bool(requires_reporting),
    }

    # Accept common alias keys from model outputs.
    alias = {
        "create_doc": "create_case_report_doc",
        "create_docs": "create_case_report_doc",
        "create_google_doc": "create_case_report_doc",
        "create_google_docs": "create_case_report_doc",
        "create_report_doc": "create_case_report_doc",
        "create_case_report": "create_case_report_doc",
    }

    resolved: dict[str, bool] = {}
    for key, default_value in defaults.items():
        val = plan.get(key)
        if val is None:
            val = plan.get(alias.get(key, ""))
        resolved[key] = bool(default_value if val is None else val)

    for src, dst in alias.items():
        if src in plan:
            resolved[dst] = bool(plan.get(src))

    return resolved


def _sanitize_manager_contract(contract: dict[str, Any], base: dict[str, Any], recovery_answers: dict[str, Any]) -> dict[str, Any]:
    raw_risk = str(contract.get("risk_level") or base.get("risk_level") or "UNKNOWN").strip().upper()
    allowed_risks = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    risk = raw_risk if raw_risk in allowed_risks else "UNKNOWN"
    scam_type = str(base.get("scam_type") or "UNKNOWN").strip() or "UNKNOWN"
    summary_base = str(base.get("summary") or base.get("victim_advice") or "").strip()

    response_mode = str(contract.get("response_mode") or "").strip().lower()
    if response_mode not in {"proactive_warning", "reactive_recovery", "apk_test_artifact", "reporting_only"}:
        if recovery_answers.get("reactive_recovery"):
            response_mode = "reactive_recovery"
        else:
            response_mode = "proactive_warning"

    verdict = str(contract.get("verdict") or "").strip()
    if _is_generic_verdict(verdict):
        verdict = "Likely scam attempt"

    category = str(
        contract.get("category")
        or contract.get("scam_type")
        or base.get("category")
        or scam_type
    ).strip() or scam_type

    summary = str(contract.get("summary") or "").strip() or summary_base or "Suspicious content analyzed."

    conversational_reply = str(contract.get("conversational_reply") or "").strip()

    confidence_raw = contract.get("confidence", base.get("confidence"))
    try:
        confidence = float(confidence_raw)
    except Exception:
        confidence = float(base.get("confidence") or 0)
    if 0 < confidence <= 1:
        confidence *= 100
    confidence = max(0.0, min(confidence, 100.0))

    raw_steps = contract.get("recommended_actions") if isinstance(contract.get("recommended_actions"), list) else []
    if not raw_steps:
        raw_steps = contract.get("action_steps") if isinstance(contract.get("action_steps"), list) else []
    action_steps = [str(x).strip() for x in raw_steps if str(x).strip()]
    if not action_steps:
        action_steps = [str(x).strip() for x in (base.get("priority_actions") or []) if str(x).strip()]
    if not action_steps and summary_base:
        action_steps = [summary_base]
    if not action_steps:
        action_steps = ["Follow the manager guidance above and monitor for any change in impact."]

    raw_evidence = contract.get("evidence") if isinstance(contract.get("evidence"), list) else []
    evidence: list[dict[str, Any]] = []
    for item in raw_evidence[:20]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or "").strip()
        if not label:
            continue
        detail = str(item.get("detail") or item.get("reason") or "").strip() or None
        try:
            confidence_item = float(item.get("confidence")) if item.get("confidence") is not None else None
        except Exception:
            confidence_item = None
        try:
            weight_item = int(round(float(item.get("weight")))) if item.get("weight") is not None else None
        except Exception:
            weight_item = None
        evidence.append({"label": label, "detail": detail, "confidence": confidence_item, "weight": weight_item})

    requires_reporting = bool(contract.get("requires_reporting", False))
    requires_emergency = bool(contract.get("requires_emergency", False))
    requires_financial_blocking = bool(
        contract.get("requires_financial_blocking", contract.get("requires_account_block", False))
    )
    golden_hour_active = bool(contract.get("golden_hour_active", base.get("golden_hour_active", False)))

    if not conversational_reply:
        conversational_reply = summary

    raw_reporting = contract.get("reporting_recommendation") if isinstance(contract.get("reporting_recommendation"), dict) else {}
    reporting_reason = str(raw_reporting.get("reason") or "").strip()
    reporting_should_report_now = bool(raw_reporting.get("should_report_now", requires_reporting))

    # Hard rule: if rationale is missing, suppress reporting-oriented output.
    if not reporting_reason:
        requires_reporting = False
        reporting_should_report_now = False

    if _is_preventive_only_case(recovery_answers):
        response_mode = "proactive_warning"
        requires_reporting = False
        requires_emergency = False
        requires_financial_blocking = False
        golden_hour_active = False
        reporting_should_report_now = False
        reporting_reason = (
            "No financial loss, link interaction, or sensitive data exposure was reported, "
            "so immediate formal reporting is not necessary."
        )
        action_steps = [
            "Do not open the suspicious link or attachment.",
            "Block the sender and mark the message as spam.",
            "Delete the suspicious message so it is not opened accidentally later.",
            "Ignore follow-up reward or urgency messages from the same source.",
        ]
        if _is_generic_verdict(verdict):
            verdict = "Likely scam attempt"
        if not summary:
            summary = "No money loss or sensitive data exposure was reported. This appears to be a prevented scam lure."

    if not conversational_reply:
        conversational_reply = summary

    requires_mcp = bool(contract.get("requires_mcp", False)) and not _is_preventive_only_case(recovery_answers)

    mcp_plan = _normalize_mcp_plan(
        requires_mcp=requires_mcp,
        raw_plan=contract.get("mcp_plan") if isinstance(contract.get("mcp_plan"), dict) else None,
        requires_reporting=requires_reporting,
    )

    reporting_recommendation = {
        "should_report_now": bool(reporting_should_report_now and requires_reporting),
        "reason": reporting_reason,
    }

    raw_sections = contract.get("presentation_sections") if isinstance(contract.get("presentation_sections"), dict) else {}
    actions_title = str(
        raw_sections.get("actions_title")
        or raw_sections.get("primary_actions_title")
        or "What to do now"
    ).strip() or "What to do now"
    status_default = (
        reporting_reason
        if reporting_reason
        else (
            "No money loss or sensitive data exposure reported."
            if _is_preventive_only_case(recovery_answers)
            else "Review the manager response and follow the recommended actions."
        )
    )
    presentation_sections = {
        "headline": str(raw_sections.get("headline") or verdict).strip() or verdict,
        "status_line": str(raw_sections.get("status_line") or status_default).strip() or status_default,
        "primary_actions_title": actions_title,
        "actions_title": actions_title,
        "evidence_title": str(raw_sections.get("evidence_title") or "Why it looks suspicious").strip() or "Why it looks suspicious",
    }

    raw_why = contract.get("why_this_decision") if isinstance(contract.get("why_this_decision"), list) else []
    why_this_decision = [str(x).strip() for x in raw_why if str(x).strip()]
    if not why_this_decision:
        why_this_decision = [str(x.get("label") or "").strip() for x in evidence if str(x.get("label") or "").strip()][:6]
    if not why_this_decision and _is_preventive_only_case(recovery_answers):
        why_this_decision = [
            "Unexpected reward lure language was detected.",
            "Shortened or obfuscated link structure is suspicious.",
            "Message relies on urgency to trigger impulsive action.",
            "Sender legitimacy was not independently verified.",
        ]

    return {
        "response_mode": response_mode,
        "verdict": verdict,
        "category": category,
        "summary": summary,
        "conversational_reply": conversational_reply,
        "risk_level": risk,
        "confidence": confidence,
        "evidence": evidence,
        "why_this_decision": why_this_decision,
        "recommended_actions": action_steps,
        "action_steps": action_steps,
        "requires_reporting": requires_reporting,
        "requires_emergency": requires_emergency,
        "requires_financial_blocking": requires_financial_blocking,
        "requires_account_block": requires_financial_blocking,
        "golden_hour_active": bool(golden_hour_active),
        "reporting_recommendation": reporting_recommendation,
        "requires_mcp": requires_mcp,
        "mcp_plan": mcp_plan,
        "presentation_sections": presentation_sections,
    }


async def _generate_manager_decision_contract(
    *,
    input_type: str,
    payload: dict[str, Any],
    base_result: dict[str, Any],
    recovery_answers: dict[str, Any],
) -> dict[str, Any]:
    payload_options = payload.get("options") if isinstance(payload.get("options"), dict) else {}
    preprocessed_context = payload.get("preprocessed_context") if isinstance(payload.get("preprocessed_context"), dict) else {}
    if not preprocessed_context:
        preprocessed_context = payload_options.get("preprocessed_context") if isinstance(payload_options.get("preprocessed_context"), dict) else {}

    context = {
        "input_type": input_type,
        "user_input_text": str(payload.get("text") or "")[:4000],
        "file_analysis": {
            "filename": payload.get("filename"),
            "mime_type": payload.get("mime_type"),
            "apk_static_summary": payload.get("static_results"),
        },
        "preprocessed_context": preprocessed_context,
        "recovery_answers": recovery_answers,
        "user_context": payload.get("user_context") if isinstance(payload.get("user_context"), dict) else {},
        "agent_outputs": {
            "risk_level": base_result.get("risk_level"),
            "scam_type": base_result.get("scam_type"),
            "confidence": base_result.get("confidence"),
            "summary": base_result.get("summary") or base_result.get("victim_advice"),
            "red_flags": base_result.get("red_flags"),
            "pattern_matches": base_result.get("pattern_matches"),
            "osint": base_result.get("osint"),
            "entities": base_result.get("extracted_entities"),
        },
    }

    prompt = (
        "You are the final decision-maker for SATARK, a citizen-facing cyber-fraud triage system.\n\n"
        "Your job is to produce the final verdict, the final action plan, and the final presentation-ready fields.\n"
        "The UI is NOT allowed to infer urgency, reporting, or emergency actions from risk score, confidence, category, or similar-case retrieval.\n"
        "Only you decide those booleans and the exact wording.\n\n"
        "PRIMARY RULE\n"
        "- Think first from user impact, not scam taxonomy.\n"
        "- Prioritize the user's reported outcomes over pattern matches.\n"
        "- Pattern matches, category labels, confidence, and similar cases are supporting evidence only.\n"
        "- Do NOT recommend reporting, hotline escalation, cybercrime filing, emergency action, banking freeze, malware scan, or device isolation unless the facts justify it.\n\n"
        "CASE STATE PRIORITY\n"
        "Use these facts as the main decision drivers:\n"
        "1. Did the user lose money?\n"
        "2. Did the user click/open/install anything?\n"
        "3. Did the user share OTP, password, CVV, UPI PIN, bank details, Aadhaar, PAN, or other sensitive details?\n"
        "4. Is there account compromise, active unauthorized access, or an ongoing attack?\n"
        "5. Is there only an unsolicited scam attempt that was ignored?\n\n"
        "MANDATORY DECISION POLICY\n"
        "A) If user says:\n"
        "- no money lost\n"
        "- no sensitive details shared\n"
        "- no OTP/password/bank details shared\n"
        "- no app installed\n"
        "- no link clicked\n"
        "Then:\n"
        "- requires_reporting = false\n"
        "- requires_emergency = false\n"
        "- requires_financial_blocking = false\n"
        "- golden_hour_active = false\n"
        "- tone must be calm-preventive, not urgent\n"
        "- actions must focus on prevention only:\n"
        "  - do not click\n"
        "  - block sender\n"
        "  - mark as spam\n"
        "  - delete message\n"
        "  - optionally monitor only if relevant\n"
        "- DO NOT mention 1930\n"
        "- DO NOT mention cybercrime.gov.in\n"
        "- DO NOT mention FIR\n"
        "- DO NOT mention malware scan or internet disconnect unless the user actually clicked/opened/installed something\n\n"
        "B) If the user clicked the link or installed something, but no money/details loss yet:\n"
        "- requires_reporting may be false or true depending on exposure\n"
        "- requires_emergency may be true only if there is credible compromise risk\n"
        "- action steps must be specific to click/install exposure\n\n"
        "C) If the user shared sensitive data, OTP, banking details, or lost money:\n"
        "- reporting/emergency may be true\n"
        "- give exact reasons\n"
        "- give exact response steps in priority order\n\n"
        "D) Risk level and confidence DO NOT automatically trigger reporting or emergency.\n"
        "A CRITICAL model score without user harm or exposure does NOT justify hotline/report filing instructions.\n\n"
        "WHAT TO DO NOW QUALITY RULES\n"
        "- Return exactly 4 actions.\n"
        "- Each action must begin with a verb.\n"
        "- Each action must be under 14 words.\n"
        "- Each action must be specific to the case facts.\n"
        "- Do not use vague actions like 'stay careful', 'secure your device', 'take precautions', or 'be alert'.\n"
        "- If no click occurred, do not mention malware, scans, or disconnecting internet.\n"
        "- If no money/details were lost, do not mention reporting, complaint filing, helplines, or account blocking.\n"
        "- In preventive-only cases, actions must be plain and practical.\n\n"
        "REPORTING RATIONALE RULES\n"
        "You MUST always fill reporting_recommendation with:\n"
        "- should_report_now: true or false\n"
        "- reason: one explicit sentence\n\n"
        "If should_report_now is false, the reason must explain why reporting is not currently needed.\n\n"
        "VERDICT RULES\n"
        "- Verdict must be meaningful. Never use 'Analysis complete' as a verdict.\n"
        "- Good verdict examples:\n"
        "  - Likely scam attempt\n"
        "  - Prevented phishing lure\n"
        "  - Active compromise risk\n"
        "  - Financial fraud requiring immediate action\n\n"
        "TONE RULES\n"
        "- Preventive cases: calm, firm, non-alarmist\n"
        "- Exposure/loss cases: urgent, direct\n"
        "- Do not use panic wording unless the facts justify it\n\n"
        "OUTPUT REQUIREMENTS\n"
        "Return valid JSON only.\n"
        "Required schema:\n"
        "{\n"
        '  "verdict": "...",\n'
        '  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",\n'
        '  "confidence": 0.0,\n'
        '  "category": "...",\n'
        '  "summary": "...",\n'
        '  "conversational_reply": "...",\n'
        '  "recommended_actions": ["...", "...", "..."],\n'
        '  "requires_reporting": true,\n'
        '  "requires_emergency": false,\n'
        '  "requires_financial_blocking": false,\n'
        '  "golden_hour_active": false,\n'
        '  "reporting_recommendation": {"should_report_now": false, "reason": "..."},\n'
        '  "why_this_decision": ["..."],\n'
        '  "presentation_sections": {"headline": "...", "status_line": "...", "actions_title": "What to do now", "evidence_title": "Why it looks suspicious"},\n'
        '  "requires_mcp": true/false,\n'
        '  "mcp_plan": {"create_calendar": true/false, "create_tasks": true/false, "create_gmail_draft": true/false, "create_case_report_doc": true/false}\n'
        "}\n\n"
        "SELF-CHECK BEFORE FINALIZING\n"
        "- Did I treat user harm/exposure as more important than scam pattern labels?\n"
        "- If no click/no loss/no details shared, are reporting/emergency all false?\n"
        "- Did I avoid 1930/cybercrime instructions unless explicitly justified?\n"
        "- Is the verdict meaningful instead of generic?\n"
        "- Is What to do now concrete and specific?\n"
        "- Did I provide a reporting rationale even when reporting is false?\n"
        "If any answer is no, revise the output before returning JSON.\n\n"
        "Pinned example:\n"
        "Example input facts:\n"
        "- SMS promises Rs 3,000 VIP gift\n"
        "- suspicious short link\n"
        "- user did NOT click\n"
        "- user did NOT lose money\n"
        "- user did NOT share personal details\n"
        "- user did NOT share banking details\n\n"
        "Example output behavior:\n"
        "- verdict: Likely scam attempt\n"
        "- requires_reporting: false\n"
        "- requires_emergency: false\n"
        "- requires_financial_blocking: false\n"
        "- golden_hour_active: false\n"
        "- reporting_recommendation.reason: No financial loss, link interaction, or sensitive data exposure was reported, so immediate formal reporting is not necessary.\n"
        "- recommended_actions:\n"
        "  1. Do not open the shortened link.\n"
        "  2. Block the sender and mark the SMS as spam.\n"
        "  3. Delete the message so it is not clicked accidentally later.\n"
        "  4. Ignore further follow-up messages from the same sender.\n"
        "- prohibited content:\n"
        "  - no 1930\n"
        "  - no cybercrime portal\n"
        "  - no malware scan\n"
        "  - no disconnect internet\n"
        "  - no urgent banner language\n\n"
        f"Case context:\n{json.dumps(context, ensure_ascii=True)[:24000]}"
    )

    contract: dict[str, Any] = {}
    try:
        resp = genai_client.models.generate_content(
            model=MODEL_FLASH,
            contents=[genai_types.Content(role="user", parts=[genai_types.Part(text=prompt)])],
            config=genai_types.GenerateContentConfig(
                temperature=0.1,
                thinking_config=genai_types.ThinkingConfig(thinking_level="MINIMAL"),
                tool_config=genai_types.ToolConfig(
                    function_calling_config=genai_types.FunctionCallingConfig(mode="NONE")
                ),
                response_mime_type="application/json",
            ),
        )

        text = ""
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            for part in candidates[0].content.parts or []:
                t = getattr(part, "text", None)
                if isinstance(t, str) and t:
                    text += t
        if text.strip():
            parsed = _parse_agent_response(text.strip())
            if isinstance(parsed, dict):
                contract = parsed
    except Exception as exc:
        logger.warning("manager.decision_contract_failed error=%s", exc)

    contract = await _audit_manager_decision_contract(
        candidate_contract=contract,
        context=context,
    )

    return _sanitize_manager_contract(contract, base_result, recovery_answers)


async def _audit_manager_decision_contract(
    *,
    candidate_contract: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(candidate_contract, dict) or not candidate_contract:
        return candidate_contract if isinstance(candidate_contract, dict) else {}

    audit_prompt = (
        "You are the SATARK response auditor.\n\n"
        "Check whether the final JSON violates any presentation rules.\n\n"
        "Fail the response if ANY of the following are true:\n"
        "- reporting/emergency is recommended without clear user-harm rationale\n"
        "- the verdict is generic, such as Analysis complete\n"
        "- What to do now contains vague actions\n"
        "- 1930/cybercrime/FIR is mentioned when there was no click, no money loss, and no sensitive data shared\n"
        "- malware/device-isolation advice appears without click/install evidence\n"
        "- reporting_recommendation.reason is missing or generic\n"
        "- tone is alarmist for a preventive-only case\n\n"
        "If the response fails, rewrite the JSON so it complies.\n"
        "Return corrected JSON only.\n\n"
        f"Case context:\n{json.dumps(context, ensure_ascii=True)[:22000]}\n\n"
        f"Candidate JSON:\n{json.dumps(candidate_contract, ensure_ascii=True)[:16000]}"
    )

    try:
        resp = genai_client.models.generate_content(
            model=MODEL_FLASH,
            contents=[genai_types.Content(role="user", parts=[genai_types.Part(text=audit_prompt)])],
            config=genai_types.GenerateContentConfig(
                temperature=0.0,
                thinking_config=genai_types.ThinkingConfig(thinking_level="MINIMAL"),
                tool_config=genai_types.ToolConfig(
                    function_calling_config=genai_types.FunctionCallingConfig(mode="NONE")
                ),
                response_mime_type="application/json",
            ),
        )

        text = ""
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            for part in candidates[0].content.parts or []:
                t = getattr(part, "text", None)
                if isinstance(t, str) and t:
                    text += t

        if text.strip():
            parsed = _parse_agent_response(text.strip())
            if isinstance(parsed, dict) and parsed:
                return parsed
    except Exception as exc:
        logger.warning("manager.decision_contract_audit_failed error=%s", exc)

    return candidate_contract


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
