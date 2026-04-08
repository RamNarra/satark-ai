from __future__ import annotations

from satark_mcp.calendar_client import create_calendar_events
from satark_mcp.notes_client import sync_notes
from satark_mcp.tasks_client import sync_tasks


def get_clients() -> dict:
    """Return MCP client callables.

    These functions are async and can be awaited from workflow code.
    """

    return {
        "calendar": create_calendar_events,
        "tasks": sync_tasks,
        "notes": sync_notes,
    }
