from __future__ import annotations

from mcp.calendar_client import create_calendar_events
from mcp.notes_client import sync_notes
from mcp.tasks_client import sync_tasks


def get_clients() -> dict:
    return {
        "calendar": create_calendar_events,
        "tasks": sync_tasks,
        "notes": sync_notes,
    }
