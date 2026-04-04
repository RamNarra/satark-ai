from __future__ import annotations

from typing import Any

from db.firestore import query_by_field, read_document, utc_now_iso, write_document

COLLECTION = "workflows"


def create_workflow(workflow_id: str, payload: dict[str, Any]) -> bool:
    doc = {
        "workflow_id": workflow_id,
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        **payload,
    }
    return write_document(COLLECTION, workflow_id, doc, merge=True)


def update_workflow(workflow_id: str, updates: dict[str, Any]) -> bool:
    payload = {"updated_at": utc_now_iso(), **updates}
    return write_document(COLLECTION, workflow_id, payload, merge=True)


def get_workflow(workflow_id: str) -> dict[str, Any] | None:
    return read_document(COLLECTION, workflow_id)


def list_session_workflows(session_id: str, limit: int = 50) -> list[dict[str, Any]]:
    rows = query_by_field(COLLECTION, "session_id", session_id, limit=limit)
    rows.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return rows
