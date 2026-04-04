from __future__ import annotations

from db.memories_repo import load_user_memory, save_user_memory


def load_context(user_id: str) -> dict:
    return load_user_memory(user_id)


def update_context(user_id: str, goal: str, tasks: list[dict]) -> dict:
    current = load_user_memory(user_id)
    recent_goals = list(current.get("recent_goals", []))
    recent_goals.insert(0, goal)
    recent_goals = recent_goals[:10]

    routines = current.get("routines", [])
    if not routines and tasks:
        routines = ["Daily planning block at 10:00", "End-of-day review at 17:30"]

    updates = {
        "recent_goals": recent_goals,
        "last_task_count": len(tasks),
        "routines": routines,
    }
    save_user_memory(user_id, updates)
    return {**current, **updates}
