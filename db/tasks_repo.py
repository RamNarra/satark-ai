from __future__ import annotations

import uuid
from typing import Any

from db.firestore import query_by_field, utc_now_iso, write_document

COLLECTION = "tasks"


def save_tasks(workflow_id: str, tasks: list[dict[str, Any]]) -> list[str]:
    now = utc_now_iso()
    ids: list[str] = []
    for item in tasks:
        task_id = item.get("task_id") or f"task_{uuid.uuid4().hex[:10]}"
        payload = {
            "task_id": task_id,
            "workflow_id": workflow_id,
            "created_at": now,
            "updated_at": now,
            **item,
        }
        ok = write_document(COLLECTION, task_id, payload, merge=True)
        if ok:
            ids.append(task_id)
    return ids


def list_tasks(workflow_id: str, limit: int = 100) -> list[dict[str, Any]]:
    return query_by_field(COLLECTION, "workflow_id", workflow_id, limit=limit)
