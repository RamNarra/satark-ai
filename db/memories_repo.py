from __future__ import annotations

from typing import Any

from db.firestore import read_document, utc_now_iso, write_document

COLLECTION = "memories"


def load_user_memory(user_id: str) -> dict[str, Any]:
    payload = read_document(COLLECTION, user_id)
    if payload is None:
        return {
            "user_id": user_id,
            "preferences": {},
            "routines": [],
            "recent_goals": [],
            "updated_at": None,
        }
    payload.setdefault("user_id", user_id)
    payload.setdefault("preferences", {})
    payload.setdefault("routines", [])
    payload.setdefault("recent_goals", [])
    return payload


def save_user_memory(user_id: str, updates: dict[str, Any]) -> bool:
    payload = {"user_id": user_id, "updated_at": utc_now_iso(), **updates}
    return write_document(COLLECTION, user_id, payload, merge=True)
