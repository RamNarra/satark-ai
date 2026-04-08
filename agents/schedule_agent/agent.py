from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _requires_meeting(task_title: str) -> bool:
    text = task_title.lower()
    return any(keyword in text for keyword in ["meeting", "call", "sync", "review", "discussion"])


def run(tasks: list[dict], timezone_name: str = "UTC") -> dict:
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=1)
    cursor = base
    events: list[dict] = []

    for task in tasks[:6]:
        duration_minutes = 45 if _requires_meeting(task.get("title", "")) else 30
        if task.get("priority") == "high":
            duration_minutes = max(duration_minutes, 60)

        event = {
            "event_id": f"evt_{task.get('task_id', 'x')}",
            "title": task.get("title", "Task block"),
            "start": cursor.isoformat(),
            "end": (cursor + timedelta(minutes=duration_minutes)).isoformat(),
            "timezone": timezone_name,
            "status": "proposed",
            "attendees": [],
            "source_agent": "schedule_agent",
        }
        events.append(event)
        cursor = cursor + timedelta(minutes=duration_minutes + 15)

    return {
        "events": events,
        "summary": f"Proposed {len(events)} calendar blocks",
    }
