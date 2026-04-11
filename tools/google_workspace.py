from __future__ import annotations

import logging
import os
import base64
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger("uvicorn.error")

# ---------------------------------------------------------------------------
# Cleanup registry — tracks created Google resources for shutdown deletion
# ---------------------------------------------------------------------------
_created_resources: list[dict[str, Any]] = []


def register_created_resource(kind: str, resource_id: str, credentials: Any, **extra: Any) -> None:
    """Register a created Google resource for later cleanup."""
    _created_resources.append({"kind": kind, "id": resource_id, "credentials": credentials, **extra})


def cleanup_all_created_resources() -> dict[str, int]:
    """Delete all registered calendar events and task lists. Called on shutdown."""
    deleted = {"calendar_events": 0, "task_lists": 0, "errors": 0}
    for item in list(_created_resources):
        try:
            creds = item.get("credentials")
            if not creds or build is None:
                continue
            if item["kind"] == "calendar_event":
                service = build("calendar", "v3", credentials=creds, cache_discovery=False)
                service.events().delete(
                    calendarId=item.get("calendar_id", "primary"),
                    eventId=item["id"],
                ).execute()
                deleted["calendar_events"] += 1
                logger.info("Cleaned up calendar event %s", item["id"])
            elif item["kind"] == "task_list":
                service = build("tasks", "v1", credentials=creds, cache_discovery=False)
                service.tasklists().delete(tasklist=item["id"]).execute()
                deleted["task_lists"] += 1
                logger.info("Cleaned up task list %s", item["id"])
        except Exception as e:
            deleted["errors"] += 1
            logger.warning("Cleanup failed for %s %s: %s", item.get("kind"), item.get("id"), e)
    _created_resources.clear()
    logger.info("Shutdown cleanup complete: %s", deleted)
    return deleted


try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
except Exception:  # pragma: no cover
    Request = None  # type: ignore
    Credentials = None  # type: ignore

try:
    from googleapiclient.discovery import build
except Exception:  # pragma: no cover
    build = None  # type: ignore

def build_google_credentials(google_oauth: dict[str, Any] | None) -> Any | None:
    if Credentials is None:
        return None
    if not google_oauth or not isinstance(google_oauth, dict):
        return None

    access_token = google_oauth.get("access_token")
    refresh_token = google_oauth.get("refresh_token")
    scopes = google_oauth.get("scopes")
    expiry = google_oauth.get("expiry")

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        return None

    token_uri = "https://oauth2.googleapis.com/token"
    creds = Credentials(
        token=str(access_token) if access_token else None,
        refresh_token=str(refresh_token) if refresh_token else None,
        token_uri=token_uri,
        client_id=client_id,
        client_secret=client_secret,
        scopes=[str(s) for s in scopes if s] if isinstance(scopes, list) else None,
    )

    if expiry:
        try:
            iso = str(expiry)
            if iso.endswith("Z"):
                iso = iso[:-1] + "+00:00"
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            # google-auth internals compare expiry against naive UTC datetimes.
            # Normalize to naive UTC to avoid offset-aware/naive comparison errors.
            creds.expiry = dt.astimezone(timezone.utc).replace(tzinfo=None)
        except Exception:
            pass

    try:
        should_refresh = (
            bool(getattr(creds, "refresh_token", None))
            and Request is not None
            and (not getattr(creds, "token", None) or getattr(creds, "expired", False))
        )
        if should_refresh:
            creds.refresh(Request())
    except Exception:
        # If refresh fails, callers should surface a re-auth message.
        pass

    return creds


def create_golden_hour_tasks(
    credentials: Any,
    *,
    case_id: str,
    scam_type: str,
    complaint_text: str = "",
) -> dict[str, Any]:
    """Create a Golden Hour checklist in Google Tasks."""
    if build is None:
        return {"attempted": False, "created": False, "error": "google_api_client_unavailable"}

    service = build("tasks", "v1", credentials=credentials, cache_discovery=False)

    tasklist = service.tasklists().insert(body={"title": f"SATARK Alerts"}).execute()
    list_id = str(tasklist.get("id") or "")

    # Track for shutdown cleanup
    if list_id:
        register_created_resource("task_list", list_id, credentials)

    tz_name = str(os.getenv("SATARK_CALENDAR_TIMEZONE") or "Asia/Kolkata")
    tz = timezone.utc
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("Asia/Kolkata")

    now_local = datetime.now(timezone.utc).astimezone(tz)

    checklist = [
        {
            "title": f"Golden Hour started — Case {case_id}",
            "notes": "You are in the first 60 minutes after financial fraud. Act immediately.",
            "offset_min": 1,
        },
        {
            "title": "Call 1930 now",
            "notes": "Share amount lost, time, transaction ID, and fraud contact details.",
            "offset_min": 5,
        },
        {
            "title": "Contact bank and freeze risky channels",
            "notes": "Ask bank or wallet provider to block or freeze suspicious transactions.",
            "offset_min": 12,
        },
        {
            "title": "Secure credentials",
            "notes": "Change passwords and protect UPI or card credentials if exposed.",
            "offset_min": 22,
        },
        {
            "title": "Preserve evidence",
            "notes": complaint_text or "Save screenshots, call logs, links, and transaction references.",
            "offset_min": 30,
        },
    ]

    task_ids: list[str] = []
    for entry in checklist:
        due_local = now_local + timedelta(minutes=int(entry.get("offset_min") or 1))
        due_utc = due_local.astimezone(timezone.utc)
        due = due_utc.isoformat().replace("+00:00", "Z")
        task = service.tasks().insert(
            tasklist=list_id,
            body={
                "title": entry["title"],
                "due": due,
                "notes": entry["notes"],
            },
        ).execute()
        tid = str(task.get("id") or "").strip()
        if tid:
            task_ids.append(tid)

    task_url = f"https://mail.google.com/mail/u/0/#tasks/all/tasks/{task_ids[0]}" if task_ids else ""

    return {
        "attempted": True,
        "created": bool(task_ids),
        "tasklist_id": list_id,
        "tasks_created": len(task_ids),
        "task_ids": task_ids,
        "task_url": task_url,
        "error": "",
    }


def create_golden_hour_calendar_events(
    credentials: Any,
    *,
    case_id: str,
    scam_type: str,
    minutes_elapsed: int | None = None,
) -> dict[str, Any]:
    """Create Golden Hour calendar timeline directly using Google Calendar API."""
    if build is None:
        return {"attempted": False, "created": False, "error": "google_api_client_unavailable"}

    service = build("calendar", "v3", credentials=credentials, cache_discovery=False)

    tz_name = str(os.getenv("SATARK_CALENDAR_TIMEZONE") or "Asia/Kolkata")
    tz = timezone.utc
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("Asia/Kolkata")
            tz_name = "Asia/Kolkata"

    try:
        elapsed_i = int(float(minutes_elapsed)) if minutes_elapsed is not None else 0
    except Exception:
        elapsed_i = 0

    remaining = max(5, 60 - max(0, elapsed_i)) if elapsed_i else 60
    first_delay_seconds = 20
    try:
        first_delay_seconds = max(0, min(120, int(os.getenv("SATARK_GOLDEN_HOUR_FIRST_EVENT_DELAY_SECONDS") or "20")))
    except Exception:
        first_delay_seconds = 20
    # Keep the first event near-immediate for demo responsiveness.
    start_base = datetime.now(timezone.utc).astimezone(tz) + timedelta(seconds=first_delay_seconds)
    in_golden_hour = elapsed_i <= 60
    lead_title = "Golden hour live now" if in_golden_hour else "Report your case now"

    event_plan = [
        {
            "title": lead_title,
            "description": (
                f"Case: {case_id}\n"
                f"Type: {scam_type}\n\n"
                f"Time remaining in golden hour window: ~{remaining} minutes\n\n"
                "Immediate steps:\n"
                "1) Call 1930\n"
                "2) Inform bank and request hold\n"
                "3) Secure credentials\n"
                "4) Preserve evidence"
            ),
            "offset_min": 0,
            "duration_min": 5,
        },
        {
            "title": "Call 1930 immediately",
            "description": "Share amount, transaction ID, and fraud contact details.",
            "offset_min": 5,
            "duration_min": 6,
        },
        {
            "title": "Contact bank and freeze risky transactions",
            "description": "Request emergency hold or block based on fraud channel used.",
            "offset_min": 12,
            "duration_min": 8,
        },
        {
            "title": "Secure credentials and preserve evidence",
            "description": "Change passwords and keep screenshots, logs, and transaction proof.",
            "offset_min": 22,
            "duration_min": 10,
        },
    ]

    created_events: list[dict[str, str]] = []
    for item in event_plan:
        start_dt = start_base + timedelta(minutes=int(item["offset_min"]))
        end_dt = start_dt + timedelta(minutes=int(item["duration_min"]))
        body = {
            "summary": item["title"],
            "description": item["description"],
            "start": {"dateTime": start_dt.isoformat(), "timeZone": tz_name},
            "end": {"dateTime": end_dt.isoformat(), "timeZone": tz_name},
            "reminders": {
                "useDefault": False,
                "overrides": [
                    {"method": "popup", "minutes": 0},
                    {"method": "popup", "minutes": 1},
                ],
            },
        }
        created = service.events().insert(calendarId="primary", body=body).execute()
        eid = str(created.get("id") or "")
        created_events.append(
            {
                "event_id": eid,
                "event_url": str(created.get("htmlLink") or ""),
                "title": str(created.get("summary") or item["title"]),
                "start_time": str(((created.get("start") or {}).get("dateTime") or "")),
            }
        )
        # Track for shutdown cleanup
        if eid:
            register_created_resource("calendar_event", eid, credentials, calendar_id="primary")

    first = created_events[0] if created_events else {}
    return {
        "attempted": True,
        "created": bool(created_events),
        "events_created": len(created_events),
        "event_id": str(first.get("event_id") or ""),
        "event_url": str(first.get("event_url") or ""),
        "title": str(first.get("title") or ""),
        "start_time": str(first.get("start_time") or ""),
        "description": "Golden Hour timeline created",
        "events": created_events,
        "error": "",
    }


def create_case_report_doc(
    credentials: Any,
    *,
    case_id: str,
    title: str,
    report_text: str,
) -> dict[str, Any]:
    """Create a styled Google Doc FIR report and set share access to anyone with link."""
    if build is None:
        return {"attempted": False, "created": False, "error": "google_api_client_unavailable"}

    docs_service = build("docs", "v1", credentials=credentials, cache_discovery=False)
    drive_service = build("drive", "v3", credentials=credentials, cache_discovery=False)

    doc = docs_service.documents().create(body={"title": title}).execute()
    doc_id = str(doc.get("documentId") or "")

    if not doc_id:
        return {
            "attempted": True,
            "created": False,
            "doc_id": "",
            "doc_url": "",
            "error": "doc_create_failed",
        }

    heading = "First Information Report"
    body_text = (report_text or "").strip() or (
        "Incident details are currently limited. Please update this report with a full timeline, "
        "sender details, transaction references, and supporting evidence."
    )
    composed_text = f"{heading}\n\n{body_text}\n"

    heading_start = 1
    heading_end = heading_start + len(heading)
    heading_para_end = heading_end + 1
    body_start = heading_start + len(f"{heading}\n\n")
    body_end = body_start + len(body_text)

    docs_service.documents().batchUpdate(
        documentId=doc_id,
        body={
            "requests": [
                {
                    "insertText": {
                        "location": {"index": 1},
                        "text": composed_text,
                    }
                },
                {
                    "updateParagraphStyle": {
                        "range": {"startIndex": heading_start, "endIndex": heading_para_end},
                        "paragraphStyle": {"alignment": "CENTER"},
                        "fields": "alignment",
                    }
                },
                {
                    "updateTextStyle": {
                        "range": {"startIndex": heading_start, "endIndex": heading_end},
                        "textStyle": {
                            "weightedFontFamily": {"fontFamily": "Times New Roman"},
                            "fontSize": {"magnitude": 20, "unit": "PT"},
                            "underline": True,
                            "bold": True,
                        },
                        "fields": "weightedFontFamily,fontSize,underline,bold",
                    }
                },
                {
                    "updateTextStyle": {
                        "range": {"startIndex": body_start, "endIndex": max(body_start, body_end)},
                        "textStyle": {
                            "weightedFontFamily": {"fontFamily": "Times New Roman"},
                            "fontSize": {"magnitude": 12, "unit": "PT"},
                        },
                        "fields": "weightedFontFamily,fontSize",
                    }
                },
            ]
        },
    ).execute()

    sharing_error = ""
    try:
        drive_service.permissions().create(
            fileId=doc_id,
            body={"type": "anyone", "role": "reader"},
            fields="id",
        ).execute()
    except Exception as exc:
        sharing_error = str(exc)

    return {
        "attempted": True,
        "created": True,
        "doc_id": doc_id,
        "doc_url": f"https://docs.google.com/document/d/{doc_id}",
        "sharing": "anyone_with_link_view",
        "error": sharing_error,
    }


def create_gmail_draft(
    credentials: Any,
    *,
    to_email: str,
    subject: str,
    body_text: str,
) -> dict[str, Any]:
    """Create a Gmail draft and return a direct draft URL when possible."""
    if build is None:
        return {"attempted": False, "created": False, "error": "google_api_client_unavailable"}

    service = build("gmail", "v1", credentials=credentials, cache_discovery=False)

    msg = EmailMessage()
    msg["To"] = to_email or ""
    msg["Subject"] = subject or "SATARK cyber incident report draft"
    msg.set_content(body_text or "")

    encoded = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    draft = service.users().drafts().create(userId="me", body={"message": {"raw": encoded}}).execute()

    draft_id = str(draft.get("id") or "").strip()
    message_id = str((draft.get("message") or {}).get("id") or "").strip() if isinstance(draft.get("message"), dict) else ""
    draft_url = f"https://mail.google.com/mail/u/0/#drafts?compose={message_id}" if message_id else ""

    return {
        "attempted": True,
        "created": bool(draft_id),
        "draft_id": draft_id,
        "message_id": message_id,
        "draft_url": draft_url,
        "error": "",
    }
