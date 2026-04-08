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


def set_google_oauth(session_id: str, oauth_payload: dict) -> bool:
    now = utc_now_iso()
    payload = {
        "google_oauth": {
            **(oauth_payload or {}),
            "updated_at": now,
        },
        "updated_at": now,
    }
    return write_document(COLLECTION, session_id, payload, merge=True)


def get_google_oauth(session_id: str) -> dict | None:
    if not session_id:
        return None
    session = get_session(session_id)
    if not session:
        return None
    oauth = session.get("google_oauth")
    return oauth if isinstance(oauth, dict) else None


def clear_google_oauth(session_id: str) -> bool:
    if not session_id:
        return False
    now = utc_now_iso()
    payload = {
        "google_oauth": {
            "access_token": None,
            "refresh_token": None,
            "scopes": None,
            "expiry": None,
            "email": None,
            "given_name": None,
            "family_name": None,
            "name": None,
            "picture": None,
            "cleared_at": now,
            "updated_at": now,
        },
        "updated_at": now,
    }
    return write_document(COLLECTION, session_id, payload, merge=True)


def set_google_oauth_pkce(session_id: str, pkce_payload: dict) -> bool:
    if not session_id:
        return False
    now = utc_now_iso()
    payload = {
        "google_oauth_pkce": {
            **(pkce_payload or {}),
            "updated_at": now,
        },
        "updated_at": now,
    }
    return write_document(COLLECTION, session_id, payload, merge=True)


def get_google_oauth_pkce(session_id: str) -> dict | None:
    if not session_id:
        return None
    session = get_session(session_id)
    if not session:
        return None
    pkce = session.get("google_oauth_pkce")
    return pkce if isinstance(pkce, dict) else None


def clear_google_oauth_pkce(session_id: str) -> bool:
    if not session_id:
        return False
    now = utc_now_iso()
    payload = {
        "google_oauth_pkce": {
            "state": None,
            "code_verifier": None,
            "used_at": now,
            "updated_at": now,
        },
        "updated_at": now,
    }
    return write_document(COLLECTION, session_id, payload, merge=True)
