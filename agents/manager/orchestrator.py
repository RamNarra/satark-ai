from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from agents.manager.contracts import PlanStep, WorkflowPlan
from agents.memory_agent import agent as memory_agent
from agents.notes_agent import agent as notes_agent
from agents.research_agent import agent as research_agent
from agents.schedule_agent import agent as schedule_agent
from agents.task_agent import agent as task_agent
from db.artifacts_repo import save_artifacts
from db.events_repo import save_events
from db.notes_repo import save_notes
from db.sessions_repo import upsert_session
from db.tasks_repo import save_tasks
from db.workflows_repo import create_workflow, update_workflow
from satark_mcp.registry import get_clients

EmitFn = Callable[[str, dict[str, Any]], Awaitable[None]]


def _intent_tags(goal: str) -> list[str]:
    text = goal.lower()
    tags = []
    if any(k in text for k in ["schedule", "calendar", "meeting", "week"]):
        tags.append("scheduling")
    if any(k in text for k in ["task", "todo", "follow-up", "action"]):
        tags.append("tasking")
    if any(k in text for k in ["note", "summary", "summarize"]):
        tags.append("notes")
    if not tags:
        tags.append("general_planning")
    return tags


def _build_plan(goal: str) -> WorkflowPlan:
    tags = _intent_tags(goal)
    steps = [
        PlanStep(step=1, agent="memory_agent", action="load_user_context"),
        PlanStep(step=2, agent="notes_agent", action="summarize_input", mode="parallel"),
        PlanStep(step=3, agent="task_agent", action="extract_tasks", mode="parallel"),
        PlanStep(step=4, agent="research_agent", action="fill_context_gaps"),
        PlanStep(step=5, agent="schedule_agent", action="propose_calendar"),
        PlanStep(step=6, agent="manager", action="merge_and_persist"),
    ]
    return WorkflowPlan(
        intent_tags=tags,
        steps=steps,
        parallel_groups=[["notes_agent", "task_agent"]],
        success_criteria=["tasks_created", "events_proposed", "notes_saved"],
    )


async def run_productivity_workflow(
    workflow_id: str,
    session_id: str,
    payload: dict[str, Any],
    emit_event: EmitFn,
) -> dict[str, Any]:
    user_id = str(payload.get("user_id") or "demo_user")
    goal = str(payload.get("goal") or "").strip()
    context = payload.get("context") or {}
    timezone_name = str(context.get("timezone") or "UTC")
    context_notes = context.get("notes") or []

    plan = _build_plan(goal)
    upsert_session(session_id, user_id, goal, channel=str(context.get("channel") or "web-ui"))
    create_workflow(
        workflow_id,
        {
            "session_id": session_id,
            "user_id": user_id,
            "goal": goal,
            "status": "running",
            "intent_tags": plan.intent_tags,
            "step_order": [f"{s.step}:{s.agent}:{s.action}" for s in plan.steps],
            "agent_trace": [],
        },
    )

    await emit_event(
        "run.classified",
        {
            "workflow_id": workflow_id,
            "session_id": session_id,
            "intent_tags": plan.intent_tags,
            "selected_agents": [
                "manager",
                "memory_agent",
                "notes_agent",
                "task_agent",
                "research_agent",
                "schedule_agent",
            ],
        },
    )

    await emit_event("agent.started", {"agent": "memory_agent", "status": "booting"})
    memory_context = await asyncio.to_thread(memory_agent.load_context, user_id)
    await emit_event("agent.completed", {"agent": "memory_agent", "status": "done", "output": {"summary": "Memory loaded"}})

    await emit_event("agent.started", {"agent": "notes_agent", "status": "running"})
    await emit_event("agent.started", {"agent": "task_agent", "status": "running"})

    notes_out, tasks_out = await asyncio.gather(
        asyncio.to_thread(notes_agent.run, goal, context_notes, memory_context.get("preferences", {})),
        asyncio.to_thread(task_agent.run, goal, []),
    )

    await emit_event("agent.completed", {"agent": "notes_agent", "status": "done", "output": {"summary": notes_out.get("summary", "")}})
    await emit_event("agent.completed", {"agent": "task_agent", "status": "done", "output": {"summary": tasks_out.get("summary", "")}})

    tasks = tasks_out.get("tasks", [])

    await emit_event("agent.started", {"agent": "research_agent", "status": "running"})
    research_out = await asyncio.to_thread(research_agent.run, goal, tasks)
    await emit_event("agent.completed", {"agent": "research_agent", "status": "done", "output": {"summary": research_out.get("summary", "")}})

    await emit_event("agent.started", {"agent": "schedule_agent", "status": "running"})
    schedule_out = await asyncio.to_thread(schedule_agent.run, tasks, timezone_name)
    await emit_event("agent.completed", {"agent": "schedule_agent", "status": "done", "output": {"summary": schedule_out.get("summary", "")}})

    await emit_event("tool.called", {"tool": "firestore.persist", "status": "running"})
    note_ids = save_notes(workflow_id, notes_out.get("notes", []))
    task_ids = save_tasks(workflow_id, tasks)
    event_ids = save_events(workflow_id, schedule_out.get("events", []))

    artifacts = [
        {
            "type": "task_list",
            "label": "Generated Tasks",
            "payload": {"task_ids": task_ids, "count": len(task_ids)},
        },
        {
            "type": "calendar_plan",
            "label": "Proposed Calendar",
            "payload": {"event_ids": event_ids, "count": len(event_ids)},
        },
        {
            "type": "notes_summary",
            "label": "Workflow Notes",
            "payload": {"note_ids": note_ids, "count": len(note_ids)},
        },
    ]
    artifact_ids = save_artifacts(workflow_id, artifacts)

    mcp_results: dict[str, Any] = {}
    options = payload.get("options") if isinstance(payload.get("options"), dict) else {}
    auto_execute_tools = bool(options.get("auto_execute_tools", True))
    if auto_execute_tools:
        clients = get_clients()
        max_events = int(payload.get("mcp_max_events") or 4)
        max_tasks = int(payload.get("mcp_max_tasks") or 8)
        max_notes = int(payload.get("mcp_max_notes") or 4)

        await emit_event("tool.called", {"tool": "mcp.sync", "status": "running"})
        try:
            calendar_fn = clients.get("calendar")
            tasks_fn = clients.get("tasks")
            notes_fn = clients.get("notes")

            sync_jobs = []
            if callable(calendar_fn):
                sync_jobs.append(calendar_fn((schedule_out.get("events") or [])[:max_events]))
            if callable(tasks_fn):
                sync_jobs.append(tasks_fn(tasks[:max_tasks]))
            if callable(notes_fn):
                sync_jobs.append(notes_fn((notes_out.get("notes") or [])[:max_notes]))

            results = await asyncio.gather(*sync_jobs, return_exceptions=True)
            for item in results:
                if isinstance(item, Exception):
                    continue
                tool_name = str(item.get("tool") or "").strip()
                if tool_name:
                    mcp_results[tool_name] = item

            await emit_event(
                "tool.result",
                {
                    "tool": "mcp.sync",
                    "status": "ok",
                    "results": {k: (v.get("status") if isinstance(v, dict) else "unknown") for k, v in mcp_results.items()},
                },
            )
        except Exception as exc:
            await emit_event(
                "tool.result",
                {
                    "tool": "mcp.sync",
                    "status": "error",
                    "error": str(exc),
                },
            )

    updated_memory = await asyncio.to_thread(memory_agent.update_context, user_id, goal, tasks)
    await emit_event(
        "tool.result",
        {
            "tool": "firestore.persist",
            "status": "ok",
            "saved": {
                "tasks": len(task_ids),
                "events": len(event_ids),
                "notes": len(note_ids),
                "artifacts": len(artifact_ids),
            },
        },
    )

    final_result = {
        "workflow_id": workflow_id,
        "session_id": session_id,
        "status": "completed",
        "goal": goal,
        "tasks": tasks,
        "events": schedule_out.get("events", []),
        "notes": notes_out.get("notes", []),
        "artifacts": artifacts,
        "plan": plan.model_dump(),
        "outputs": {
            "notes": notes_out,
            "tasks": tasks_out,
            "research": research_out,
            "schedule": schedule_out,
            "mcp": mcp_results,
            "memory": {
                "recent_goals": updated_memory.get("recent_goals", []),
                "routines": updated_memory.get("routines", []),
            },
        },
        "artifact_ids": artifact_ids,
        "summary": {
            "tasks_created": len(task_ids),
            "events_proposed": len(event_ids),
            "notes_saved": len(note_ids),
        },
    }

    update_workflow(
        workflow_id,
        {
            "status": "completed",
            "result": final_result,
            "agent_trace": [
                "memory_agent:completed",
                "notes_agent:completed",
                "task_agent:completed",
                "research_agent:completed",
                "schedule_agent:completed",
                "manager:merged",
            ],
        },
    )
    return final_result
