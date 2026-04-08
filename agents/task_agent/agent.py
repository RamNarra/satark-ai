from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone


def _split_goal_into_items(goal: str) -> list[str]:
    parts = re.split(r"[\n,;]|\band\b", goal)
    cleaned = [p.strip(" .") for p in parts if p and p.strip()]
    return cleaned


def _priority_for_item(item: str) -> str:
    text = item.lower()
    if any(keyword in text for keyword in ["urgent", "asap", "critical", "today"]):
        return "high"
    if any(keyword in text for keyword in ["important", "priority", "deadline", "follow-up"]):
        return "medium"
    return "low"


def _deadline_for_item(item: str) -> str | None:
    text = item.lower()
    now = datetime.now(timezone.utc)
    if any(keyword in text for keyword in ["urgent", "asap", "critical", "immediately", "now", "golden hour", "1930"]):
        return (now + timedelta(minutes=5)).isoformat()
    if "today" in text:
        return now.isoformat()
    if "tomorrow" in text:
        return (now + timedelta(days=1)).isoformat()
    if "this week" in text or "weekly" in text:
        return (now + timedelta(days=5)).isoformat()
    return None


def run(goal: str, notes_bullets: list[str] | None = None) -> dict:
    seeds = _split_goal_into_items(goal)
    if notes_bullets:
        seeds.extend([b.strip() for b in notes_bullets if b and b.strip()])

    tasks: list[dict] = []
    seen: set[str] = set()
    for idx, item in enumerate(seeds, start=1):
        key = item.lower()
        if len(item) < 4 or key in seen:
            continue
        seen.add(key)
        tasks.append(
            {
                "task_id": f"tsk_{idx:03d}",
                "title": item[0].upper() + item[1:],
                "description": f"Derived from workflow goal: {goal[:120]}",
                "priority": _priority_for_item(item),
                "deadline": _deadline_for_item(item),
                "status": "pending",
                "source_agent": "task_agent",
            }
        )

    if not tasks:
        tasks = [
            {
                "task_id": "tsk_001",
                "title": "Clarify workflow objective",
                "description": "No explicit task candidates found in input.",
                "priority": "medium",
                "deadline": None,
                "status": "pending",
                "source_agent": "task_agent",
            }
        ]

    return {
        "tasks": tasks,
        "summary": f"Generated {len(tasks)} task candidates",
    }
