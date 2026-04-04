from __future__ import annotations

import uuid
from typing import Any

from db.firestore import query_by_field, utc_now_iso, write_document

COLLECTION = "events"


def save_events(workflow_id: str, events: list[dict[str, Any]]) -> list[str]:
    now = utc_now_iso()
    ids: list[str] = []
    for item in events:
        event_id = item.get("event_id") or f"event_{uuid.uuid4().hex[:10]}"
        payload = {
            "event_id": event_id,
            "workflow_id": workflow_id,
            "created_at": now,
            "updated_at": now,
            **item,
        }
        ok = write_document(COLLECTION, event_id, payload, merge=True)
        if ok:
            ids.append(event_id)
    return ids


def list_events(workflow_id: str, limit: int = 100) -> list[dict[str, Any]]:
    return query_by_field(COLLECTION, "workflow_id", workflow_id, limit=limit)
