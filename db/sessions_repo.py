from __future__ import annotations

from db.firestore import read_document, utc_now_iso, write_document

COLLECTION = "sessions"


def upsert_session(
    session_id: str,
    user_id: str,
    last_prompt: str,
    channel: str = "web-ui",
    status: str = "active",
) -> bool:
    now = utc_now_iso()
    payload = {
        "session_id": session_id,
        "user_id": user_id,
        "last_prompt": last_prompt,
        "channel": channel,
        "status": status,
        "updated_at": now,
        "created_at": now,
    }
    return write_document(COLLECTION, session_id, payload, merge=True)


def get_session(session_id: str) -> dict | None:
    return read_document(COLLECTION, session_id)
