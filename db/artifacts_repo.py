from __future__ import annotations

import uuid
from typing import Any

from db.firestore import query_by_field, read_document, utc_now_iso, write_document

COLLECTION = "artifacts"


def save_artifacts(workflow_id: str, artifacts: list[dict[str, Any]]) -> list[str]:
    now = utc_now_iso()
    ids: list[str] = []
    for item in artifacts:
        artifact_id = item.get("artifact_id") or f"art_{uuid.uuid4().hex[:10]}"
        payload = {
            "artifact_id": artifact_id,
            "workflow_id": workflow_id,
            "approval_status": item.get("approval_status", "pending"),
            "created_at": now,
            "updated_at": now,
            **item,
        }
        ok = write_document(COLLECTION, artifact_id, payload, merge=True)
        if ok:
            ids.append(artifact_id)
    return ids


def list_artifacts(workflow_id: str, limit: int = 100) -> list[dict[str, Any]]:
    return query_by_field(COLLECTION, "workflow_id", workflow_id, limit=limit)


def approve_artifact(artifact_id: str, approved_by: str) -> dict[str, Any] | None:
    existing = read_document(COLLECTION, artifact_id)
    if existing is None:
        return None
    updated = {
        "approval_status": "approved",
        "approved_by": approved_by,
        "approved_at": utc_now_iso(),
    }
    ok = write_document(COLLECTION, artifact_id, updated, merge=True)
    if not ok:
        return None
    merged = {**existing, **updated}
    return merged
