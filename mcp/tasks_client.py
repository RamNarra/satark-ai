from __future__ import annotations


def sync_tasks(tasks: list[dict]) -> dict:
    return {
        "tool": "tasks_mcp",
        "status": "stub",
        "synced": 0,
        "tasks": tasks,
    }
