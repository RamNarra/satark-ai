from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

from agents.manager.orchestrator import run_productivity_workflow
from api.schemas import (
    ArtifactApprovalRequest,
    ChatRequest,
    SessionSnapshot,
    WorkflowRunAccepted,
    WorkflowRunRequest,
)
from api.stream import sse_event
from db.artifacts_repo import approve_artifact, list_artifacts
from db.events_repo import list_events
from db.notes_repo import list_notes
from db.sessions_repo import get_session
from db.tasks_repo import list_tasks
from db.workflows_repo import get_workflow, list_session_workflows, update_workflow

router = APIRouter(tags=["workflow"])

WORKFLOW_RUNTIME: dict[str, dict[str, Any]] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _as_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _normalize_workflow_result(workflow_id: str, session_id: str | None, result: dict[str, Any] | None) -> dict[str, Any]:
    result = result or {}
    outputs = result.get("outputs") if isinstance(result.get("outputs"), dict) else {}

    tasks = _as_list(result.get("tasks"))
    events = _as_list(result.get("events"))
    notes = _as_list(result.get("notes"))

    if not tasks:
        tasks_out = outputs.get("tasks")
        if isinstance(tasks_out, dict):
            tasks = _as_list(tasks_out.get("tasks"))
        elif isinstance(tasks_out, list):
            tasks = _as_list(tasks_out)

    if not events:
        schedule_out = outputs.get("schedule")
        if isinstance(schedule_out, dict):
            events = _as_list(schedule_out.get("events"))
        elif isinstance(schedule_out, list):
            events = _as_list(schedule_out)

    if not notes:
        notes_out = outputs.get("notes")
        if isinstance(notes_out, dict):
            notes = _as_list(notes_out.get("notes"))
        elif isinstance(notes_out, list):
            notes = _as_list(notes_out)

    if not tasks:
        tasks = list_tasks(workflow_id)
    if not events:
        events = list_events(workflow_id)
    if not notes:
        notes = list_notes(workflow_id)

    artifacts = _as_list(result.get("artifacts"))
    if not artifacts:
        artifacts = list_artifacts(workflow_id)

    artifact_ids = result.get("artifact_ids") if isinstance(result.get("artifact_ids"), list) else []
    if not artifact_ids:
        artifact_ids = [a.get("artifact_id") for a in artifacts if a.get("artifact_id")]

    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    merged_summary = {
        **summary,
        "tasks_created": len(tasks),
        "events_proposed": len(events),
        "notes_saved": len(notes),
    }

    return {
        **result,
        "workflow_id": result.get("workflow_id") or workflow_id,
        "session_id": result.get("session_id") or session_id,
        "tasks": tasks,
        "events": events,
        "notes": notes,
        "artifacts": artifacts,
        "artifact_ids": artifact_ids,
        "summary": merged_summary,
    }


async def _emit_event(workflow_id: str, event_name: str, payload: dict[str, Any]) -> None:
    runtime = WORKFLOW_RUNTIME.get(workflow_id)
    if not runtime:
        return

    enriched = {
        "workflow_id": workflow_id,
        "timestamp": _utc_now(),
        **payload,
    }
    event = {"event": event_name, "data": enriched}
    runtime.setdefault("events", []).append(event)

    for queue in list(runtime.get("subscribers", [])):
        await queue.put(event)


async def _finish_event_stream(workflow_id: str) -> None:
    runtime = WORKFLOW_RUNTIME.get(workflow_id)
    if not runtime:
        return
    for queue in list(runtime.get("subscribers", [])):
        await queue.put(None)


async def _execute_workflow(workflow_id: str) -> None:
    runtime = WORKFLOW_RUNTIME.get(workflow_id)
    if not runtime:
        return

    try:
        runtime["status"] = "running"
        result = await run_productivity_workflow(
            workflow_id=workflow_id,
            session_id=runtime["session_id"],
            payload=runtime["request"],
            emit_event=lambda event_name, payload: _emit_event(workflow_id, event_name, payload),
        )
        runtime["status"] = "completed"
        runtime["result"] = result
        await _emit_event(
            workflow_id,
            "run.completed",
            {
                "session_id": runtime["session_id"],
                "workflow_url": f"/workflow/{workflow_id}",
                "summary": result.get("summary", {}),
            },
        )
    except Exception as exc:
        runtime["status"] = "failed"
        runtime["error"] = str(exc)
        update_workflow(workflow_id, {"status": "failed", "error": str(exc)})
        await _emit_event(
            workflow_id,
            "run.failed",
            {
                "session_id": runtime["session_id"],
                "error": str(exc),
            },
        )
    finally:
        await _finish_event_stream(workflow_id)


async def _start_workflow(request_payload: dict[str, Any]) -> WorkflowRunAccepted:
    workflow_id = _new_id("wf")
    session_id = request_payload.get("session_id") or _new_id("sess")

    WORKFLOW_RUNTIME[workflow_id] = {
        "workflow_id": workflow_id,
        "session_id": session_id,
        "request": {**request_payload, "session_id": session_id},
        "status": "accepted",
        "result": None,
        "error": None,
        "events": [],
        "subscribers": [],
    }

    await _emit_event(
        workflow_id,
        "run.accepted",
        {
            "session_id": session_id,
            "status": "accepted",
        },
    )
    asyncio.create_task(_execute_workflow(workflow_id))

    return WorkflowRunAccepted(
        workflow_id=workflow_id,
        session_id=session_id,
        status="accepted",
        stream_url=f"/workflow/{workflow_id}/stream",
        workflow_url=f"/workflow/{workflow_id}",
    )


@router.post("/workflow/run", response_model=WorkflowRunAccepted)
async def workflow_run(req: WorkflowRunRequest):
    return await _start_workflow(req.model_dump())


@router.post("/chat", response_model=WorkflowRunAccepted)
async def chat(req: ChatRequest):
    payload = WorkflowRunRequest(
        session_id=req.session_id,
        user_id=req.user_id,
        goal=req.message,
    ).model_dump()
    return await _start_workflow(payload)


@router.get("/workflow/{workflow_id}")
async def workflow_get(workflow_id: str):
    runtime = WORKFLOW_RUNTIME.get(workflow_id)
    if runtime:
        if runtime["status"] in {"accepted", "running"}:
            return JSONResponse(
                status_code=202,
                content={
                    "workflow_id": workflow_id,
                    "session_id": runtime["session_id"],
                    "status": runtime["status"],
                    "message": "Workflow still in progress",
                },
            )
        if runtime["status"] == "failed":
            return {
                "workflow_id": workflow_id,
                "session_id": runtime["session_id"],
                "status": "failed",
                "error": runtime["error"],
            }
        return _normalize_workflow_result(workflow_id, runtime["session_id"], runtime.get("result"))

    doc = get_workflow(workflow_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="workflow_id not found")

    if doc.get("result"):
        return _normalize_workflow_result(workflow_id, doc.get("session_id"), doc["result"])

    fallback_result = {
        "workflow_id": workflow_id,
        "session_id": doc.get("session_id"),
        "status": doc.get("status", "unknown"),
        "goal": doc.get("goal", ""),
        "tasks": list_tasks(workflow_id),
        "events": list_events(workflow_id),
        "notes": list_notes(workflow_id),
        "artifacts": list_artifacts(workflow_id),
    }
    return _normalize_workflow_result(workflow_id, doc.get("session_id"), fallback_result)


@router.get("/workflow/{workflow_id}/stream")
async def workflow_stream(workflow_id: str):
    runtime = WORKFLOW_RUNTIME.get(workflow_id)
    if runtime is None:
        raise HTTPException(status_code=404, detail="workflow_id not found in active runtime")

    queue: asyncio.Queue = asyncio.Queue()
    history = list(runtime.get("events", []))
    runtime.setdefault("subscribers", []).append(queue)

    async def _generator():
        try:
            for event in history:
                yield sse_event(event["event"], event["data"])

            while True:
                current = WORKFLOW_RUNTIME.get(workflow_id) or {}
                if current.get("status") in {"completed", "failed"} and queue.empty():
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\\n\\n"
                    continue

                if item is None:
                    break
                yield sse_event(item["event"], item["data"])
        finally:
            current = WORKFLOW_RUNTIME.get(workflow_id)
            if current and queue in current.get("subscribers", []):
                current["subscribers"].remove(queue)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/stream/{workflow_id}")
async def stream_alias(workflow_id: str):
    return await workflow_stream(workflow_id)


@router.get("/sessions/{session_id}", response_model=SessionSnapshot)
async def session_get(session_id: str):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session_id not found")
    workflows = list_session_workflows(session_id)
    return SessionSnapshot(
        session_id=session_id,
        user_id=session.get("user_id", "unknown"),
        status=session.get("status", "active"),
        workflows=workflows,
    )


@router.post("/artifacts/{artifact_id}/approve")
async def artifact_approve(artifact_id: str, req: ArtifactApprovalRequest):
    approved = approve_artifact(artifact_id, req.approved_by)
    if approved is None:
        raise HTTPException(status_code=404, detail="artifact_id not found")
    return {
        "artifact_id": artifact_id,
        "approval_status": approved.get("approval_status", "approved"),
        "approved_by": approved.get("approved_by", req.approved_by),
    }
