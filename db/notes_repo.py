from __future__ import annotations

import uuid
from typing import Any

from db.firestore import query_by_field, utc_now_iso, write_document

COLLECTION = "notes"


def save_notes(workflow_id: str, notes: list[dict[str, Any]]) -> list[str]:
    now = utc_now_iso()
    ids: list[str] = []
    for item in notes:
        note_id = item.get("note_id") or f"note_{uuid.uuid4().hex[:10]}"
        payload = {
            "note_id": note_id,
            "workflow_id": workflow_id,
            "created_at": now,
            "updated_at": now,
            **item,
        }
        ok = write_document(COLLECTION, note_id, payload, merge=True)
        if ok:
            ids.append(note_id)
    return ids


def list_notes(workflow_id: str, limit: int = 100) -> list[dict[str, Any]]:
    return query_by_field(COLLECTION, "workflow_id", workflow_id, limit=limit)
