import os, sys
import asyncio
import json
import mimetypes
import uuid
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import Any, Optional
import uvicorn
from agents.manager import run_pipeline
from agents.manager.agent import run as run_legacy_pipeline
from db.operations import (
    find_similar_patterns,
    get_case_stats,
    save_case,
    save_fraud_pattern,
)
from db.client import get_db
from fastapi.staticfiles import StaticFiles
import base64
from urllib.parse import urlparse
from config import PROJECT_ID, LOCATION, GEMINI_LIVE_MODEL
from api.workflow_api import router as workflow_router

try:
    from google import genai
    from google.genai import types as genai_types
except Exception:
    genai = None  # type: ignore
    genai_types = None  # type: ignore


LIVE_STREAM_INSTRUCTION = (
    "You are SATARK AI, a real-time cyber fraud analyst. "
    "As live audio arrives, return concise TEXT updates with: "
    "RISK (SAFE|MEDIUM|HIGH|CRITICAL), likely scam type, and immediate next action. "
    "When confidence is high, explicitly advise 1930 and cybercrime.gov.in."
)


live_client = (
    genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    if genai is not None
    else None
)

app = FastAPI(
    title="SATARK AI",
    description="Smart Anti-fraud Technology for Awareness, Reporting & Knowledge",
    version="1.0.0"
)

app.include_router(workflow_router)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/ui")
def serve_ui():
    return FileResponse("frontend/ui.html")


@app.get("/ops")
def serve_ops():
    return FileResponse("frontend/index.html")


@app.get("/")
def serve_root_ui():
    return FileResponse("frontend/ui.html")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


class AnalyzeFile(BaseModel):
    file_name: str
    file_type: Optional[str] = None
    file_url: Optional[str] = None
    content_base64: Optional[str] = None


class AnalyzeUserInput(BaseModel):
    text: str = ""
    language_hint: Optional[str] = None
    files: list[AnalyzeFile] = Field(default_factory=list)


class AnalyzeUserContext(BaseModel):
    location: Optional[str] = None
    channel: str = "web-ui"


class AnalyzeOptions(BaseModel):
    stream: bool = True
    generate_report: bool = True
    trigger_mcp_actions: bool = False


class AnalyzeRequestV1(BaseModel):
    session_id: Optional[str] = None
    user_input: AnalyzeUserInput
    user_context: AnalyzeUserContext = Field(default_factory=AnalyzeUserContext)
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


RUN_STORE: dict[str, dict] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _normalize_agent(agent: str) -> str:
    alias = {
        "manager": "manager",
        "scam": "scam_detector",
        "scam_detector": "scam_detector",
        "audio": "audio_analyzer",
        "audio_analyzer": "audio_analyzer",
        "apk": "apk_analyzer",
        "apk_analyzer": "apk_analyzer",
        "osint": "osint",
        "golden": "golden_hour",
        "golden_hour": "golden_hour",
    }
    return alias.get(agent, agent)


def _classify_flow(user_input: dict) -> tuple[str, list[str]]:
    files = user_input.get("files") or []
    text = str(user_input.get("text") or "").lower()

    def _is_audio(file_item: dict) -> bool:
        ft = str(file_item.get("file_type") or "")
        fn = str(file_item.get("file_name") or "")
        return ft.startswith("audio/") or fn.lower().endswith((".mp3", ".wav", ".m4a", ".ogg"))

    def _is_apk(file_item: dict) -> bool:
        ft = str(file_item.get("file_type") or "")
        fn = str(file_item.get("file_name") or "")
        return ft == "application/vnd.android.package-archive" or fn.lower().endswith(".apk")

    has_audio = any(_is_audio(f) for f in files)
    has_apk = any(_is_apk(f) for f in files)
    has_image = any(str(f.get("file_type") or "").startswith("image/") for f in files)

    primary_type = "text"
    if has_audio and has_apk:
        primary_type = "audio_apk"
    elif has_audio:
        primary_type = "audio"
    elif has_apk:
        primary_type = "apk"
    elif has_image:
        primary_type = "text_image"

    selected_agents = ["manager", "scam_detector", "osint", "golden_hour"]
    if has_audio or any(k in text for k in ["voice", "call", "audio", "recording"]):
        selected_agents.insert(2, "audio_analyzer")
    if has_apk:
        selected_agents.insert(2, "apk_analyzer")

    deduped = []
    for agent in selected_agents:
        norm = _normalize_agent(agent)
        if norm not in deduped:
            deduped.append(norm)
    return primary_type, deduped


def _decode_b64(data: str) -> bytes:
    clean = (data or "").strip()
    if not clean:
        return b""
    if "," in clean and ";base64" in clean.split(",", 1)[0]:
        clean = clean.split(",", 1)[1]
    padding = len(clean) % 4
    if padding:
        clean += "=" * (4 - padding)
    return base64.b64decode(clean)


def _select_best_file(files: list[dict]) -> Optional[dict]:
    if not files:
        return None

    def score(item: dict) -> int:
        fn = str(item.get("file_name") or "").lower()
        ft = str(item.get("file_type") or "")
        if fn.endswith(".apk") or ft == "application/vnd.android.package-archive":
            return 100
        if ft.startswith("audio/") or fn.endswith((".mp3", ".wav", ".m4a", ".ogg")):
            return 90
        if ft.startswith("image/"):
            return 80
        return 10

    return sorted(files, key=score, reverse=True)[0]


def _build_similarity_context(similar: list[dict]) -> str:
    if not similar:
        return ""
    lines = []
    for item in similar[:3]:
        scam_type = str(item.get("scam_type") or "UNKNOWN")
        score = int(item.get("score") or 0)
        sub_type = str(item.get("sub_type") or "")
        if sub_type:
            lines.append(f"- {scam_type}/{sub_type} ({score}% match)")
        else:
            lines.append(f"- {scam_type} ({score}% match)")
    return "Similar known patterns:\n" + "\n".join(lines)


def _build_pipeline_call(user_input: dict, similar: Optional[list[dict]] = None) -> tuple[str, dict]:
    text = str(user_input.get("text") or "").strip()
    files = user_input.get("files") or []
    selected = _select_best_file(files)
    similarity_context = _build_similarity_context(similar or [])
    effective_text = text
    if similarity_context:
        effective_text = f"{text}\n\n{similarity_context}" if text else similarity_context

    payload = {
        "text": effective_text,
        "fraud_amount": 0,
        "minutes_since_fraud": None,
    }

    if not selected:
        return "text", payload

    file_name = str(selected.get("file_name") or "evidence.bin")
    file_type = str(selected.get("file_type") or mimetypes.guess_type(file_name)[0] or "application/octet-stream")
    content_b64 = selected.get("content_base64")

    if not content_b64:
        # Metadata-only file (e.g. cloud URI). Keep analysis text-first while preserving flow classification.
        return "text", payload

    raw = _decode_b64(str(content_b64))

    if file_name.lower().endswith(".apk") or file_type == "application/vnd.android.package-archive":
        from agents.apk_analyzer.agent import run_static_analysis

        static_results = run_static_analysis(raw, file_name)
        return "apk", {
            "filename": file_name,
            "static_results": static_results,
            "text": effective_text,
        }

    if file_type.startswith("audio/") or file_name.lower().endswith((".mp3", ".wav", ".m4a", ".ogg")):
        return "audio", {
            "audio_b64": base64.b64encode(raw).decode("utf-8"),
            "filename": file_name,
            "mime_type": file_type,
            "text": effective_text,
            "fraud_amount": 0,
            "minutes_since_fraud": None,
        }

    return "image", {
        "image_b64": base64.b64encode(raw).decode("utf-8"),
        "filename": file_name,
        "mime_type": file_type,
        "text": effective_text,
        "fraud_amount": 0,
        "minutes_since_fraud": None,
    }


def _build_legacy_input(user_input: dict) -> dict:
    text = str(user_input.get("text") or "").strip()
    files = user_input.get("files") or []
    selected = _select_best_file(files)
    if not selected:
        return {"type": "text", "text": text}

    file_name = str(selected.get("file_name") or "evidence.bin")
    file_type = str(selected.get("file_type") or mimetypes.guess_type(file_name)[0] or "application/octet-stream")
    content_b64 = selected.get("content_base64")
    if not content_b64:
        return {"type": "text", "text": text}

    raw = _decode_b64(str(content_b64))
    if file_name.lower().endswith(".apk") or file_type == "application/vnd.android.package-archive":
        return {"type": "apk", "bytes": raw, "filename": file_name}
    if file_type.startswith("audio/") or file_name.lower().endswith((".mp3", ".wav", ".m4a", ".ogg")):
        return {"type": "audio", "bytes": raw, "mime_type": file_type, "text": text}
    if file_type.startswith("image/"):
        return {"type": "image", "bytes": raw, "mime_type": file_type, "text": text}
    return {"type": "text", "text": text}


def _needs_legacy_fallback(pipeline_result: dict) -> bool:
    stages = pipeline_result.get("pipeline_stages") or []
    if isinstance(stages, list) and any(str(s).endswith("detection_failed") for s in stages):
        return True
    err_text = str(pipeline_result.get("error") or "").lower()
    if "resource_exhausted" in err_text or "quota exceeded" in err_text:
        return True
    return False


def _event_line(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {json.dumps(data, ensure_ascii=True)}\n\n"


async def _emit_event(run_id: str, event_name: str, payload: dict) -> None:
    run = RUN_STORE.get(run_id)
    if not run:
        return

    merged = {"run_id": run_id, "timestamp": _utc_now(), **payload}
    event = {"event": event_name, "data": merged}
    run.setdefault("events", []).append(event)
    for q in list(run.get("subscribers", [])):
        await q.put(event)


async def _finish_streams(run_id: str) -> None:
    run = RUN_STORE.get(run_id)
    if not run:
        return
    for q in list(run.get("subscribers", [])):
        await q.put(None)


def _extract_domains(urls: list[str]) -> list[str]:
    domains = []
    for u in urls:
        candidate = str(u or "").strip()
        if not candidate:
            continue
        parsed = urlparse(candidate)
        domain = parsed.netloc or parsed.path.split("/")[0]
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _extract_stage(pipeline_result: dict, stage_name: str) -> dict:
    stages = pipeline_result.get("pipeline_stages")
    if isinstance(stages, dict):
        stage = stages.get(stage_name)
        if isinstance(stage, dict):
            return stage
    return {}


def _normalize_recommended_actions(pipeline_result: dict) -> list[str]:
    actions: list[str] = []

    priority_actions = pipeline_result.get("priority_actions")
    if isinstance(priority_actions, list):
        for item in priority_actions:
            if isinstance(item, dict):
                action = str(item.get("action") or "").strip()
                if action:
                    actions.append(action)
            elif str(item).strip():
                actions.append(str(item).strip())

    victim_advice = str(pipeline_result.get("victim_advice") or "").strip()
    if victim_advice:
        actions.append(victim_advice)

    deduped: list[str] = []
    for action in actions:
        if action not in deduped:
            deduped.append(action)

    if deduped:
        return deduped[:6]

    return [
        "Do not click suspicious links",
        "Do not share OTP or PIN",
        "Call 1930 immediately",
        "File complaint at cybercrime.gov.in",
    ]


def _load_persisted_case(run_id: str) -> Optional[dict]:
    db = get_db()
    if not db:
        return None
    try:
        doc = db.collection("cases").document(run_id).get()
        if not doc.exists:
            return None
        payload = doc.to_dict() or {}
        risk_level = str(payload.get("risk_level") or "UNKNOWN")
        confidence = int(payload.get("confidence") or 0)
        summary = str(payload.get("summary") or "Recovered case result")
        recommended = ["Call 1930 immediately", "File complaint at cybercrime.gov.in"]
        return {
            "run_id": run_id,
            "case_id": run_id,
            "status": "completed",
            "input_type": payload.get("input_type", "text"),
            "verdict": "Likely scam" if confidence >= 50 else "Needs manual review",
            "summary": summary,
            "scam_type": payload.get("scam_type", "UNKNOWN"),
            "official_category": payload.get("scam_type", "UNKNOWN"),
            "risk_level": risk_level,
            "confidence": confidence,
            "signals_found": _as_string_list(payload.get("signals_found")),
            "similar_cases": int(payload.get("similar_cases", 0) or 0),
            "golden_hour_status": "ACTIVE" if payload.get("golden_hour_active") else "STANDBY",
            "golden_hour_message": "Contact helpline 1930 and preserve evidence.",
            "entities": {
                "phone_numbers": [],
                "domains": [],
                "urls": [],
                "ips": [],
                "banks_claimed": [],
            },
            "osint": None,
            "audio_analysis": None,
            "apk_analysis": None,
            "evidence_summary": _as_string_list(payload.get("signals_found"))[:5],
            "recommended_actions": recommended,
            "complaint_draft": {
                "title": "Cyber Fraud Complaint Draft",
                "acknowledgment_id": run_id,
                "body": "I am reporting a suspected cyber fraud incident. Please investigate and initiate fund-protection steps.",
            },
            "follow_up_actions": {
                "calendar_event_created": False,
                "gmail_draft_created": False,
                "tgcsb_alert_sent": False,
            },
            "agent_results": {
                "manager": {"status": "done"},
                "scam_detector": {"status": "done"},
                "audio_analyzer": {"status": "skipped"},
                "apk_analyzer": {"status": "skipped"},
                "osint": {"status": "done"},
                "golden_hour": {"status": "done"},
            },
            "timestamps": {
                "created_at": payload.get("timestamp"),
                "completed_at": payload.get("timestamp"),
            },
            "raw": payload,
        }
    except Exception:
        return None


def _build_result_document(run_ctx: dict, pipeline_result: dict, primary_type: str, selected_agents: list[str]) -> dict:
    scam_type = str(pipeline_result.get("scam_type") or "UNKNOWN")
    risk_level = str(pipeline_result.get("risk_level") or "UNKNOWN").upper()
    confidence = int(float(pipeline_result.get("confidence") or 0))
    is_scam = bool(pipeline_result.get("is_scam", confidence >= 60))

    extracted = pipeline_result.get("extracted_entities") if isinstance(pipeline_result.get("extracted_entities"), dict) else {}
    urls = _as_string_list(extracted.get("urls"))
    phones = _as_string_list(extracted.get("phone_numbers") or extracted.get("phones"))
    ips = _as_string_list(extracted.get("ips"))
    banks_claimed = _as_string_list(extracted.get("bank_names") or extracted.get("banks_claimed"))

    osint_stage = _extract_stage(pipeline_result, "osint")
    osint_payload: Optional[dict] = None
    if "osint" in selected_agents:
        osint_payload = {
            "threat_summary": str(osint_stage.get("threat_summary") or pipeline_result.get("osint_summary") or "OSINT scan completed."),
            "overall_threat_score": int(osint_stage.get("overall_threat_score") or pipeline_result.get("threat_score") or 0),
            "domains": osint_stage.get("domains") if isinstance(osint_stage.get("domains"), dict) else {},
            "ips": osint_stage.get("ips") if isinstance(osint_stage.get("ips"), dict) else {},
            "urls": osint_stage.get("urls") if isinstance(osint_stage.get("urls"), dict) else {},
        }

    recommended_actions = _normalize_recommended_actions(pipeline_result)
    verdict = "Likely scam" if is_scam else "Likely safe"
    summary_text = str(pipeline_result.get("summary") or "").strip()
    if not summary_text:
        if is_scam:
            summary_text = "This input contains multiple indicators of cyber fraud. Avoid engaging further and start immediate reporting."
        else:
            summary_text = "No high-confidence scam pattern was confirmed, but stay cautious and verify independently."

    files = run_ctx["request"]["user_input"].get("files") or []
    evidence_summary = _as_string_list(pipeline_result.get("signals_found") or pipeline_result.get("red_flags"))
    if not evidence_summary:
        evidence_summary = [
            "Automated multi-agent analysis completed",
            "Pattern checks and response planning executed",
        ]

    similar_cases = int(
        run_ctx.get("similar_patterns_count")
        or pipeline_result.get("similar_cases_found")
        or 0
    )

    calendar_event = pipeline_result.get("calendar_event") if isinstance(pipeline_result.get("calendar_event"), dict) else {}
    fir_template = pipeline_result.get("fir_template")
    if isinstance(fir_template, dict):
        complaint_body = str(fir_template.get("case_summary") or "")
    else:
        complaint_body = str(fir_template or "")

    if not complaint_body:
        complaint_body = (
            "I am reporting a suspected cyber fraud incident and request immediate action. "
            "Please initiate evidence-based investigation and fund-protection steps."
        )

    modality_audio = None
    if "audio_analyzer" in selected_agents:
        modality_audio = {
            "summary": str(pipeline_result.get("summary") or pipeline_result.get("victim_advice") or "Audio fraud analysis completed."),
            "confidence": confidence,
            "risk_level": risk_level,
        }

    modality_apk = None
    if "apk_analyzer" in selected_agents:
        modality_apk = {
            "summary": str(pipeline_result.get("summary") or "APK static and behavioral indicators analyzed."),
            "risk_level": risk_level,
            "is_malicious": bool(pipeline_result.get("is_malicious") or is_scam),
        }

    selected_set = set(selected_agents)
    agent_results = {
        "manager": {"status": "done"},
        "scam_detector": {"status": "done" if "scam_detector" in selected_set else "skipped"},
        "audio_analyzer": {"status": "done" if "audio_analyzer" in selected_set else "skipped"},
        "apk_analyzer": {"status": "done" if "apk_analyzer" in selected_set else "skipped"},
        "osint": {"status": "done" if "osint" in selected_set else "skipped"},
        "golden_hour": {"status": "done" if "golden_hour" in selected_set else "skipped"},
    }

    return {
        "run_id": run_ctx["run_id"],
        "case_id": run_ctx["case_id"],
        "status": run_ctx["status"],
        "input_type": primary_type,
        "verdict": verdict,
        "summary": summary_text,
        "scam_type": scam_type,
        "official_category": scam_type,
        "risk_level": risk_level,
        "confidence": confidence,
        "signals_found": _as_string_list(pipeline_result.get("signals_found") or pipeline_result.get("red_flags")),
        "similar_cases": similar_cases,
        "golden_hour_status": "ACTIVE" if bool(pipeline_result.get("golden_hour_active")) else "STANDBY",
        "golden_hour_message": recommended_actions[0],
        "entities": {
            "phone_numbers": phones,
            "domains": _extract_domains(urls),
            "urls": urls,
            "ips": ips,
            "banks_claimed": banks_claimed,
        },
        "osint": osint_payload,
        "audio_analysis": modality_audio,
        "apk_analysis": modality_apk,
        "evidence_summary": evidence_summary,
        "recommended_actions": recommended_actions,
        "complaint_draft": {
            "title": "Cyber Fraud Complaint Draft",
            "acknowledgment_id": run_ctx["case_id"],
            "body": complaint_body,
        },
        "follow_up_actions": {
            "calendar_event_created": bool(calendar_event.get("created", False)),
            "gmail_draft_created": False,
            "tgcsb_alert_sent": False,
        },
        "agent_results": agent_results,
        "evidence": [
            {
                "type": f.get("file_type") or "unknown",
                "source": f.get("file_name") or "unknown",
                "storage_uri": f.get("file_url"),
            }
            for f in files
        ],
        "timestamps": {
            "created_at": run_ctx["created_at"],
            "completed_at": run_ctx.get("completed_at"),
        },
        "raw": pipeline_result,
    }


def _build_sync_report(text: str, files: list[dict], pipeline_result: dict, primary_type: str) -> dict:
    _, selected_agents = _classify_flow({"text": text, "files": files})
    now = _utc_now()
    run_ctx = {
        "run_id": str(pipeline_result.get("acknowledgment_id") or _new_id("run")),
        "case_id": str(pipeline_result.get("case_id") or _new_id("case")),
        "status": "completed",
        "created_at": now,
        "completed_at": now,
        "request": {
            "user_input": {
                "text": text,
                "files": files,
            }
        },
        "similar_patterns_count": int(pipeline_result.get("similar_cases_found") or 0),
    }
    return _build_result_document(run_ctx, pipeline_result, primary_type, selected_agents)


async def _orchestrate_run(run_id: str) -> None:
    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        return

    try:
        run_ctx["status"] = "running"
        req = run_ctx["request"]
        user_input = req["user_input"]

        primary_type, selected_agents = _classify_flow(user_input)
        run_ctx["primary_type"] = primary_type
        run_ctx["selected_agents"] = selected_agents

        await _emit_event(
            run_id,
            "run.classified",
            {
                "case_id": run_ctx["case_id"],
                "primary_type": primary_type,
                "selected_agents": selected_agents,
            },
        )

        await _emit_event(run_id, "agent.started", {"agent": "manager", "label": "Manager Agent", "status": "booting"})
        await _emit_event(
            run_id,
            "agent.progress",
            {
                "agent": "manager",
                "step": "route_planning",
                "status": "running",
                "message": "Manager selected execution graph",
            },
        )

        for agent in selected_agents:
            if agent == "manager":
                continue
            await _emit_event(
                run_id,
                "agent.started",
                {"agent": agent, "label": agent.replace("_", " ").title(), "status": "queued"},
            )

        await _emit_event(
            run_id,
            "tool.called",
            {
                "agent": "manager",
                "tool": "manager_pipeline",
                "message": "Manager delegating to selected agents",
            },
        )

        user_text = str(user_input.get("text") or "").strip()
        similar_patterns: list[dict] = []
        if user_text:
            await _emit_event(
                run_id,
                "tool.called",
                {
                    "agent": "manager",
                    "tool": "vector_pattern_lookup",
                    "message": "Searching similar historical fraud patterns",
                },
            )
            similar_patterns = find_similar_patterns(
                query_text=user_text,
                scam_type=None,
                limit=3,
                min_score=40,
            )
            await _emit_event(
                run_id,
                "tool.result",
                {
                    "agent": "manager",
                    "tool": "vector_pattern_lookup",
                    "status": "ok",
                    "matches": len(similar_patterns),
                },
            )
        run_ctx["similar_patterns_count"] = len(similar_patterns)

        input_type, payload = _build_pipeline_call(user_input, similar_patterns)
        legacy_input = _build_legacy_input(user_input)

        if run_pipeline is None:
            await _emit_event(
                run_id,
                "tool.called",
                {
                    "agent": "manager",
                    "tool": "legacy_manager_pipeline",
                    "message": "Primary pipeline unavailable, activating fallback inference path",
                },
            )
            pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
            await _emit_event(
                run_id,
                "tool.result",
                {
                    "agent": "manager",
                    "tool": "legacy_manager_pipeline",
                    "status": "ok",
                },
            )
        else:
            try:
                pipeline_result = await run_pipeline(input_type, payload)
            except Exception:
                await _emit_event(
                    run_id,
                    "tool.called",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "message": "Primary pipeline errored, activating fallback inference path",
                    },
                )
                pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
                await _emit_event(
                    run_id,
                    "tool.result",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "status": "ok",
                    },
                )

            if _needs_legacy_fallback(pipeline_result):
                await _emit_event(
                    run_id,
                    "tool.called",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "message": "Primary pipeline degraded, activating fallback inference path",
                    },
                )
                pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
                await _emit_event(
                    run_id,
                    "tool.result",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "status": "ok",
                    },
                )

        await _emit_event(
            run_id,
            "tool.result",
            {
                "agent": "manager",
                "tool": "manager_pipeline",
                "status": "ok",
            },
        )

        for agent in selected_agents:
            if agent == "manager":
                continue
            summary = "Stage completed"
            if agent == "scam_detector":
                summary = f"Risk {pipeline_result.get('risk_level', 'UNKNOWN')} | type {pipeline_result.get('scam_type', 'UNKNOWN')}"
            elif agent == "osint":
                summary = pipeline_result.get("osint_summary", "OSINT correlation complete") or "OSINT complete"
            elif agent == "golden_hour":
                summary = "Priority response actions generated"
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": agent,
                    "status": "done",
                    "output": {
                        "summary": summary,
                    },
                },
            )

        await _emit_event(
            run_id,
            "agent.completed",
            {
                "agent": "manager",
                "status": "done",
                "output": {
                    "summary": "Routing and orchestration complete",
                },
            },
        )

        run_ctx["status"] = "completed"
        run_ctx["completed_at"] = _utc_now()
        run_ctx["result"] = _build_result_document(run_ctx, pipeline_result, primary_type, selected_agents)

        result = run_ctx["result"]
        scam_type = str(result.get("scam_type") or "UNKNOWN")
        risk_level = str(result.get("risk_level") or "UNKNOWN")
        confidence = float(result.get("confidence") or 0)
        input_type = str(result.get("input_type") or primary_type)
        golden_hour_active = str(result.get("golden_hour_status") or "").upper() == "ACTIVE"
        summary_text = str(result.get("summary") or "")

        save_case(
            acknowledgment_id=run_id,
            case_data={
                "scam_type": scam_type,
                "risk_level": risk_level,
                "confidence": confidence,
                "golden_hour_active": golden_hour_active,
                "input_type": input_type,
                "summary": summary_text,
            },
        )

        final_user_text = user_text
        final_scam_type = scam_type
        final_confidence = float(confidence or 0)
        if final_user_text and final_scam_type.upper() not in {"UNKNOWN", "NONE", ""}:
            save_fraud_pattern(final_user_text, final_scam_type, final_confidence)

        await _emit_event(
            run_id,
            "run.completed",
            {
                "case_id": run_ctx["case_id"],
                "result_url": f"/api/result/{run_id}",
            },
        )
    except Exception as e:
        run_ctx["status"] = "failed"
        run_ctx["completed_at"] = _utc_now()
        run_ctx["error"] = str(e)
        await _emit_event(
            run_id,
            "run.failed",
            {
                "case_id": run_ctx["case_id"],
                "error": str(e),
            },
        )
    finally:
        await _finish_streams(run_id)

class TextRequest(BaseModel):
    text: str
    fraud_amount: Optional[float] = 0
    minutes_since_fraud: Optional[int] = None

@app.get("/api")
def api_root():
    return {
        "service": "SATARK AI",
        "status": "online",
        "version": "1.0.0",
        "helpline": "1930",
        "portal": "cybercrime.gov.in",
    }

@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/api/health")
def api_health():
    return {
        "status": "healthy",
        "service": "satark-api",
        "timestamp": _utc_now(),
    }


@app.post("/api/analyze")
async def api_analyze(req: AnalyzeRequestV1):
    run_id = _new_id("run")
    case_id = _new_id("case")

    RUN_STORE[run_id] = {
        "run_id": run_id,
        "case_id": case_id,
        "status": "accepted",
        "created_at": _utc_now(),
        "completed_at": None,
        "request": req.model_dump(),
        "result": None,
        "error": None,
        "events": [],
        "subscribers": [],
    }

    await _emit_event(
        run_id,
        "run.accepted",
        {
            "case_id": case_id,
            "status": "accepted",
        },
    )

    asyncio.create_task(_orchestrate_run(run_id))

    return {
        "run_id": run_id,
        "case_id": case_id,
        "status": "accepted",
        "stream_url": f"/api/stream/{run_id}",
        "result_url": f"/api/result/{run_id}",
    }


@app.get("/api/stream/{run_id}")
async def api_stream(run_id: str):
    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        raise HTTPException(status_code=404, detail="run_id not found")

    queue: asyncio.Queue = asyncio.Queue()
    history = list(run_ctx.get("events", []))
    run_ctx.setdefault("subscribers", []).append(queue)

    async def stream_generator():
        try:
            for evt in history:
                yield _event_line(evt["event"], evt["data"])

            while True:
                current = RUN_STORE.get(run_id) or {}
                if current.get("status") in {"completed", "failed"} and queue.empty():
                    break
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue

                if evt is None:
                    break
                yield _event_line(evt["event"], evt["data"])
        finally:
            latest = RUN_STORE.get(run_id)
            if latest and queue in latest.get("subscribers", []):
                latest["subscribers"].remove(queue)

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/result/{run_id}")
async def api_result(run_id: str):
    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        persisted = _load_persisted_case(run_id)
        if persisted is None:
            raise HTTPException(status_code=404, detail="run_id not found")
        return persisted

    status = run_ctx.get("status")
    if status in {"accepted", "running"}:
        return JSONResponse(
            status_code=202,
            content={
                "run_id": run_id,
                "case_id": run_ctx.get("case_id"),
                "status": status,
                "message": "Run still in progress",
            },
        )

    if status == "failed":
        return {
            "run_id": run_id,
            "case_id": run_ctx.get("case_id"),
            "status": "failed",
            "error": run_ctx.get("error", "Unknown error"),
            "timestamps": {
                "created_at": run_ctx.get("created_at"),
                "completed_at": run_ctx.get("completed_at"),
            },
        }

    return run_ctx.get("result")


@app.get("/stats")
def stats():
    return get_case_stats()


@app.post("/analyze")
async def analyze_unified(
    text: Optional[str] = Form(None),
    file: UploadFile | None = File(None),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None),
):
    try:
        if file is None and (text is None or not text.strip()):
            raise HTTPException(status_code=400, detail="Provide text and/or file")

        if file is None:
            result = await run_pipeline(
                "text",
                {
                    "text": (text or "").strip(),
                    "fraud_amount": fraud_amount,
                    "minutes_since_fraud": minutes_since_fraud,
                },
            )
            report = _build_sync_report(
                text=(text or "").strip(),
                files=[],
                pipeline_result=result,
                primary_type="text",
            )
            return JSONResponse(content=report)

        content = await file.read()
        filename = file.filename or "uploaded_file"
        mime_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

        if ext == "apk" or mime_type == "application/vnd.android.package-archive":
            from agents.apk_analyzer.agent import run_static_analysis

            static_results = run_static_analysis(content, filename)
            result = await run_pipeline(
                "apk",
                {
                    "filename": filename,
                    "static_results": static_results,
                    "text": (text or "").strip(),
                },
            )
            report = _build_sync_report(
                text=(text or "").strip(),
                files=[{"file_name": filename, "file_type": mime_type}],
                pipeline_result=result,
                primary_type="apk",
            )
            return JSONResponse(content=report)

        if mime_type.startswith("audio/"):
            audio_b64 = base64.b64encode(content).decode("utf-8")
            result = await run_pipeline(
                "audio",
                {
                    "audio_b64": audio_b64,
                    "filename": filename,
                    "mime_type": mime_type,
                    "text": (text or "").strip(),
                    "fraud_amount": fraud_amount,
                    "minutes_since_fraud": minutes_since_fraud,
                },
            )
            report = _build_sync_report(
                text=(text or "").strip(),
                files=[{"file_name": filename, "file_type": mime_type}],
                pipeline_result=result,
                primary_type="audio",
            )
            return JSONResponse(content=report)

        image_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline(
            "image",
            {
                "image_b64": image_b64,
                "filename": filename,
                "mime_type": mime_type,
                "text": (text or "").strip(),
                "fraud_amount": fraud_amount,
                "minutes_since_fraud": minutes_since_fraud,
            },
        )
        report = _build_sync_report(
            text=(text or "").strip(),
            files=[{"file_name": filename, "file_type": mime_type}],
            pipeline_result=result,
            primary_type="text_image",
        )
        return JSONResponse(content=report)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/text")
async def analyze_text(req: TextRequest):
    try:
        result = await run_pipeline("text", {
            "text": req.text,
            "fraud_amount": req.fraud_amount,
            "minutes_since_fraud": req.minutes_since_fraud,
        })
        report = _build_sync_report(req.text, [], result, "text")
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/image")
async def analyze_image(
    file: UploadFile = File(...),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None)
):
    try:
        content = await file.read()
        image_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline("image", {
            "image_b64": image_b64,
            "filename": file.filename,
            "mime_type": file.content_type or "image/jpeg",
            "fraud_amount": fraud_amount,
            "minutes_since_fraud": minutes_since_fraud,
        })
        report = _build_sync_report(
            "",
            [{"file_name": file.filename or "upload.jpg", "file_type": file.content_type or "image/jpeg"}],
            result,
            "text_image",
        )
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/audio")
async def analyze_audio(
    file: UploadFile = File(...),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None)
):
    try:
        content = await file.read()
        audio_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline("audio", {
            "audio_b64": audio_b64,
            "filename": file.filename,
            "mime_type": file.content_type or "audio/mp3",
            "fraud_amount": fraud_amount,
            "minutes_since_fraud": minutes_since_fraud,
        })
        report = _build_sync_report(
            "",
            [{"file_name": file.filename or "upload.audio", "file_type": file.content_type or "audio/mp3"}],
            result,
            "audio",
        )
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/apk")
async def analyze_apk(file: UploadFile = File(...)):
    try:
        content = await file.read()
        from agents.apk_analyzer.agent import run_static_analysis
        static_results = run_static_analysis(content, file.filename)
        result = await run_pipeline("apk", {
            "filename": file.filename,
            "static_results": static_results,
        })
        report = _build_sync_report(
            "",
            [{"file_name": file.filename or "upload.apk", "file_type": file.content_type or "application/vnd.android.package-archive"}],
            result,
            "apk",
        )
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/stream")
async def stream_audio(websocket: WebSocket):
    await websocket.accept()

    if live_client is None or genai_types is None:
        await websocket.send_json({"type": "error", "message": "google-genai live SDK is unavailable"})
        await websocket.close(code=1011)
        return

    model_name = GEMINI_LIVE_MODEL
    mime_type = "audio/webm"
    stop_event = asyncio.Event()

    try:
        async with live_client.aio.live.connect(
            model=model_name,
            config={
                "response_modalities": ["AUDIO"],
                "input_audio_transcription": {},
                "output_audio_transcription": {},
            },
        ) as session:
            await session.send_client_content(
                turns={"role": "user", "parts": [{"text": LIVE_STREAM_INSTRUCTION}]},
                turn_complete=False,
            )

            async def receive_browser_audio():
                nonlocal mime_type
                while not stop_event.is_set():
                    message = await websocket.receive()

                    if message.get("type") == "websocket.disconnect":
                        stop_event.set()
                        break

                    if message.get("bytes") is not None:
                        chunk = message["bytes"]
                        if chunk:
                            await session.send_realtime_input(
                                audio=genai_types.Blob(data=chunk, mime_type=mime_type)
                            )
                        continue

                    text_msg = (message.get("text") or "").strip()
                    if not text_msg:
                        continue

                    try:
                        payload = json.loads(text_msg)
                    except Exception:
                        await session.send_realtime_input(text=text_msg)
                        continue

                    event_type = payload.get("type")
                    if event_type == "config" and payload.get("mime_type"):
                        mime_type = str(payload.get("mime_type"))
                    elif event_type == "audio_end":
                        await session.send_realtime_input(audio_stream_end=True)
                    elif event_type == "text" and payload.get("text"):
                        await session.send_realtime_input(text=str(payload.get("text")))

                stop_event.set()

            async def forward_live_analysis():
                while not stop_event.is_set():
                    async for chunk in session.receive():
                        if chunk.text:
                            await websocket.send_json({"type": "analysis", "text": chunk.text})
                        if (
                            chunk.server_content
                            and chunk.server_content.input_transcription
                            and chunk.server_content.input_transcription.text
                        ):
                            await websocket.send_json(
                                {
                                    "type": "analysis",
                                    "text": f"CALLER: {chunk.server_content.input_transcription.text}",
                                }
                            )
                        if (
                            chunk.server_content
                            and chunk.server_content.output_transcription
                            and chunk.server_content.output_transcription.text
                        ):
                            await websocket.send_json(
                                {
                                    "type": "analysis",
                                    "text": f"SATARK: {chunk.server_content.output_transcription.text}",
                                }
                            )
                        if chunk.server_content and chunk.server_content.turn_complete:
                            await websocket.send_json({"type": "turn_complete"})
                        if stop_event.is_set():
                            break

                stop_event.set()

            in_task = asyncio.create_task(receive_browser_audio())
            out_task = asyncio.create_task(forward_live_analysis())

            done, pending = await asyncio.wait(
                [in_task, out_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            stop_event.set()

            for task in pending:
                task.cancel()

            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, WebSocketDisconnect):
                    await websocket.send_json({"type": "error", "message": str(exc)})

            try:
                await session.send_realtime_input(audio_stream_end=True)
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port)