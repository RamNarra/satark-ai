from __future__ import annotations

import re


def _to_bullets(text: str) -> list[str]:
    parts = re.split(r"[\n.;]", text)
    bullets = [p.strip(" -") for p in parts if p and p.strip()]
    return bullets[:8]


def run(goal: str, context_notes: list[str] | None = None, memory_preferences: dict | None = None) -> dict:
    context_notes = context_notes or []
    memory_preferences = memory_preferences or {}
    bullets = _to_bullets(goal)
    summary = goal.strip()
    if len(summary) > 220:
        summary = summary[:217] + "..."

    style = memory_preferences.get("note_style") if isinstance(memory_preferences, dict) else None
    if style == "concise":
        bullets = bullets[:4]

    note = {
        "title": "Workflow Brief",
        "summary": summary,
        "bullets": bullets,
        "source_refs": context_notes[:4],
        "source_agent": "notes_agent",
    }
    return {
        "notes": [note],
        "summary": "Structured notes prepared",
    }
