from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from google.cloud.firestore_v1.base_query import FieldFilter

from db.client import get_db


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_document(collection: str, doc_id: str, payload: dict[str, Any], merge: bool = True) -> bool:
    db = get_db()
    if not db:
        return False
    try:
        db.collection(collection).document(doc_id).set(payload, merge=merge)
        return True
    except Exception:
        return False


def read_document(collection: str, doc_id: str) -> dict[str, Any] | None:
    db = get_db()
    if not db:
        return None
    try:
        doc = db.collection(collection).document(doc_id).get()
        if not doc.exists:
            return None
        payload = doc.to_dict() or {}
        payload.setdefault("id", doc.id)
        return payload
    except Exception:
        return None


def query_by_field(collection: str, field_name: str, value: Any, limit: int = 100) -> list[dict[str, Any]]:
    db = get_db()
    if not db:
        return []
    try:
        query = db.collection(collection).where(filter=FieldFilter(field_name, "==", value)).limit(limit)
        rows: list[dict[str, Any]] = []
        for doc in query.stream():
            payload = doc.to_dict() or {}
            payload.setdefault("id", doc.id)
            rows.append(payload)
        return rows
    except Exception:
        return []
