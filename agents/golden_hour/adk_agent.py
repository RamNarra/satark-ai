import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from google.adk.agents import Agent
from google.genai import types

from config import GEMINI_FLASH_MODEL

try:
    from google.adk.tools import MCPToolset
    from google.adk.tools.mcp_tool.mcp_toolset import StdioConnectionParams
except Exception:
    MCPToolset = None  # type: ignore
    StdioConnectionParams = None  # type: ignore


def _build_calendar_mcp_env(
    google_oauth: dict[str, Any] | None,
    *,
    session_id: str | None,
) -> dict[str, str] | None:
    env: dict[str, str] = {}
    for key in [
        "GOOGLE_OAUTH_CREDENTIALS",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GOOGLE_CALENDAR_MCP_TOKEN_PATH",
        "GOOGLE_ACCOUNT_MODE",
        "OPENAPI_MCP_HEADERS",
        "GOOGLE_CALENDAR_ID",
        "SATARK_CALENDAR_TIMEZONE",
    ]:
        value = os.getenv(key)
        if value:
            env[key] = value

    _ensure_google_oauth_credentials_file(env)

    cred_path = env.get("GOOGLE_OAUTH_CREDENTIALS")
    if not cred_path:
        return None
    try:
        p = Path(cred_path).expanduser().resolve()
        if not p.exists():
            return None
        env["GOOGLE_OAUTH_CREDENTIALS"] = str(p)
    except Exception:
        return None

    account_id = _safe_account_id(session_id)
    _maybe_write_calendar_mcp_tokens(env, google_oauth, account_id=account_id)
    if not env.get("GOOGLE_CALENDAR_MCP_TOKEN_PATH"):
        return None

    # Keep tool surface tight.
    env.setdefault("ENABLED_TOOLS", "create-event,get-current-time")
    return env


def _extract_text_from_mcp_response(resp: dict[str, Any]) -> str:
    content = resp.get("content")
    if not isinstance(content, list):
        return ""
    for part in content:
        if isinstance(part, dict) and isinstance(part.get("text"), str) and part.get("text").strip():
            return part["text"].strip()
    return ""


def _extract_event_fields(resp: dict[str, Any]) -> tuple[str | None, str | None]:
    # Best-effort extraction of {id, htmlLink} from MCP response.
    if not isinstance(resp, dict):
        return None, None
    for key in ["id", "event_id", "eventId"]:
        value = resp.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip(), None

    text = _extract_text_from_mcp_response(resp)
    if text:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                event_id = parsed.get("id") or parsed.get("event_id") or parsed.get("eventId")
                link = parsed.get("htmlLink") or parsed.get("link")

                if not event_id and isinstance(parsed.get("event"), dict):
                    nested = parsed["event"]
                    event_id = nested.get("id") or nested.get("event_id") or nested.get("eventId")
                    link = link or nested.get("htmlLink") or nested.get("link")

                eid = str(event_id).strip() if event_id else None
                lnk = str(link).strip() if link else None
                return eid, lnk
        except Exception:
            pass

    # Some MCP servers return nested payloads.
    for key in ["result", "data", "event"]:
        nested = resp.get(key)
        if isinstance(nested, dict):
            eid = nested.get("id") or nested.get("event_id") or nested.get("eventId")
            link = nested.get("htmlLink") or nested.get("link")
            if eid:
                return str(eid).strip(), (str(link).strip() if link else None)
    return None, None


async def schedule_golden_hour_calendar_events(
    *,
    google_oauth: dict[str, Any] | None,
    session_id: str | None,
    case_id: str,
    scam_type: str,
    minutes_elapsed: int | None,
) -> dict[str, Any]:
    """Create the Golden Hour staggered action reminders in Google Calendar.

        Creates 5 events (each 5 minutes) with near-immediate reminder behavior.
        The first event starts almost instantly and includes a popup at event start,
        then subsequent events are staggered across the remaining window.

    Returns a calendar_event dict compatible with the manager contract.
    """
    minutes_elapsed_i = 0
    try:
        if minutes_elapsed is not None:
            minutes_elapsed_i = max(0, int(minutes_elapsed))
    except Exception:
        minutes_elapsed_i = 0

    env = _build_calendar_mcp_env(google_oauth, session_id=session_id)
    if not env:
        return {
            "attempted": False,
            "created": False,
            "title": "",
            "event_id": "",
            "start_time": "",
            "description": "",
            "error": "calendar_mcp_not_configured",
        }

    tz_name = str(env.get("SATARK_CALENDAR_TIMEZONE") or "Asia/Kolkata")
    if ZoneInfo is None:
        tz = timezone.utc
        tz_name = "UTC"
    else:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("Asia/Kolkata")
            tz_name = "Asia/Kolkata"

    now_utc = datetime.now(timezone.utc)
    mins_remaining = max(5, 60 - minutes_elapsed_i)
    # Keep the first event near-immediate so popup appears during live demo flow.
    base_shift = 0.34  # ~20 seconds
    last_offset = max(0, mins_remaining - 5) + base_shift

    immediate_title = "Golden hour live now" if minutes_elapsed_i <= 60 else "Report your case now"
    immediate_desc = (
        f"Case {case_id}\n\n"
        f"You have ~{mins_remaining} minutes left to recover funds.\n\n"
        "IMMEDIATE STEPS:\n"
        "1) Call 1930 now\n"
        "2) File at https://cybercrime.gov.in\n"
        "3) Contact your bank to block/freeze\n"
    )

    account = None
    if isinstance(google_oauth, dict):
        acct = google_oauth.get("calendar_mcp_account_id")
        if isinstance(acct, str) and re.fullmatch(r"[a-z0-9_-]{1,64}", acct.strip()):
            account = acct.strip()
    if not account and session_id:
        account = _safe_account_id(session_id)

    def _dt_str(dt: datetime) -> str:
        # MCP schema expects start/end as strings. Strip microseconds.
        return dt.replace(microsecond=0).isoformat(timespec="seconds")

    def make_event(offset_mins: float, title: str, description: str, urgent: bool) -> dict[str, Any]:
        start_dt = (now_utc + timedelta(minutes=float(offset_mins))).astimezone(tz)
        end_dt = (start_dt + timedelta(minutes=5)).astimezone(tz)
        ev: dict[str, Any] = {
            "summary": title,
            "description": description,
            "start": _dt_str(start_dt),
            "end": _dt_str(end_dt),
            "timeZone": tz_name,
            "colorId": "11" if urgent else "5",
            "reminders": {
                "useDefault": False,
                "overrides": [
                    {"method": "popup", "minutes": 0},
                    {"method": "popup", "minutes": 1},
                ],
            },
        }
        if account:
            ev["account"] = account
        return ev

    events = [
        make_event(
            base_shift,
            immediate_title,
            immediate_desc,
            urgent=True,
        ),
        make_event(
            5 + base_shift,
            "STEP 1: Call 1930 — Cyber Crime Helpline",
            (
                "Call 1930 immediately. Tell them:\n"
                "- Amount lost\n"
                "- Transaction ID\n"
                "- Fraudster phone/UPI\n\n"
                "Ask them to freeze the transaction.\n\n"
                f"Case ID: {case_id}"
            ),
            urgent=True,
        ),
        make_event(
            15 + base_shift,
            "STEP 2: File NCRP Complaint Online",
            (
                "Go to: https://cybercrime.gov.in\n"
                "Use the complaint draft from your SATARK report.\n\n"
                f"Case ID: {case_id}"
            ),
            urgent=False,
        ),
        make_event(
            30 + base_shift,
            "STEP 3: Contact Your Bank",
            (
                "Call your bank's fraud line. Ask to:\n"
                "- Block the transaction\n"
                "- Freeze account / beneficiary\n\n"
                "Keep screenshots and transaction IDs ready.\n\n"
                f"Case ID: {case_id}"
            ),
            urgent=False,
        ),
        make_event(
            last_offset,
            "⚠️ GOLDEN HOUR ENDS IN 5 MINUTES",
            (
                "Last chance to file at https://cybercrime.gov.in\n"
                "After this window, fund recovery becomes much harder.\n\n"
                f"Case ID: {case_id}"
            ),
            urgent=True,
        ),
    ]

    from satark_mcp.runtime import (
        McpServerSpec,
        call_mcp_tool,
        choose_tool_name,
        list_mcp_tools,
        open_stdio_session,
        parse_json_list_env,
    )

    command = os.getenv("SATARK_CALENDAR_MCP_COMMAND", "npx").strip() or "npx"
    args = parse_json_list_env("SATARK_CALENDAR_MCP_ARGS") or ["-y", "@cocal/google-calendar-mcp"]

    calendar_id = str(os.getenv("GOOGLE_CALENDAR_ID") or "primary")

    created_ids: list[str] = []
    first_event_id: str = ""
    first_start: str = ""
    first_desc: str = ""
    first_title: str = ""
    first_error: str = ""

    try:
        session = await open_stdio_session(McpServerSpec(command=command, args=args, env=env, timeout_s=30.0))
        tools = await list_mcp_tools(session)
        tool_names = [str(t.get("name") or "") for t in tools]
        explicit_tool = os.getenv("SATARK_CALENDAR_MCP_TOOL_CREATE_EVENT", "").strip()
        tool_name = choose_tool_name(
            tool_names,
            prefer=[explicit_tool] if explicit_tool else None,
            require_all_substrings=["create", "event"],
        )

        if not tool_name:
            return {
                "attempted": True,
                "created": False,
                "title": "",
                "event_id": "",
                "start_time": "",
                "description": "",
                "error": f"No calendar create-event tool found. Available: {', '.join([n for n in tool_names if n])}",
            }

        tool_def = next((t for t in tools if t.get("name") == tool_name), None) or {}
        tool_schema = tool_def.get("inputSchema") if isinstance(tool_def, dict) else None
        props = tool_schema.get("properties") if isinstance(tool_schema, dict) else None

        for idx, ev in enumerate(events):
            try:
                args_for_tool: dict[str, Any]
                if isinstance(props, dict) and "event" in props:
                    args_for_tool = {"event": ev}
                else:
                    args_for_tool = dict(ev)

                if isinstance(props, dict):
                    if "calendarId" in props:
                        args_for_tool.setdefault("calendarId", calendar_id)
                    elif "calendar_id" in props:
                        args_for_tool.setdefault("calendar_id", calendar_id)
                    elif "calendar" in props:
                        args_for_tool.setdefault("calendar", calendar_id)
                else:
                    args_for_tool.setdefault("calendarId", calendar_id)

                resp = await call_mcp_tool(session, tool_name, args_for_tool)
                eid, _link = _extract_event_fields(resp if isinstance(resp, dict) else {})
                if eid:
                    created_ids.append(eid)
                    if not first_event_id:
                        first_event_id = eid

                if idx == 0:
                    first_title = str(ev.get("summary") or "")
                    first_desc = str(ev.get("description") or "")
                    first_start = str(ev.get("start") or "")
            except Exception as exc:
                if idx == 0:
                    first_title = str(ev.get("summary") or "")
                    first_desc = str(ev.get("description") or "")
                    first_start = str(ev.get("start") or "")
                    first_error = str(exc)
                continue

        created = len(created_ids) > 0
        error = "" if created else (first_error or "calendar_event_creation_failed")
        if not first_title:
            first_title = immediate_title
        if not first_desc:
            first_desc = immediate_desc
        if not first_start:
            first_start = _dt_str((now_utc + timedelta(minutes=base_shift)).astimezone(tz))

        return {
            "attempted": True,
            "created": created,
            "title": first_title,
            "event_id": first_event_id,
            "start_time": first_start,
            "description": first_desc,
            "error": error,
        }

    except Exception as exc:
        return {
            "attempted": True,
            "created": False,
            "title": immediate_title,
            "event_id": "",
            "start_time": _dt_str((now_utc + timedelta(minutes=base_shift)).astimezone(tz)),
            "description": immediate_desc,
            "error": str(exc),
        }


def _safe_account_id(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "normal"
    raw = re.sub(r"[^a-z0-9_-]+", "_", raw)
    raw = raw.strip("_-")
    if not raw:
        return "normal"
    return raw[:64]


def _config_dir() -> Path:
    base = os.getenv("XDG_CONFIG_HOME")
    if base:
        return Path(base)
    return Path.home() / ".config"


def _write_json_secure(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _ensure_google_oauth_credentials_file(env: dict[str, str]) -> None:
    existing = env.get("GOOGLE_OAUTH_CREDENTIALS")
    if existing:
        try:
            if Path(existing).expanduser().resolve().exists():
                env["GOOGLE_OAUTH_CREDENTIALS"] = str(Path(existing).expanduser().resolve())
                return
        except Exception:
            return

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        return

    # google-calendar-mcp accepts either:
    # - {"installed": {"client_id", "client_secret", "redirect_uris": [...]}}
    # - or direct {"client_id", "client_secret", "redirect_uris": [...]}
    # It does NOT require auth_uri/token_uri in the file loader.
    redirect_uris = [
        "http://localhost:3000/oauth2callback",
        "http://127.0.0.1:3000/oauth2callback",
    ]

    credentials_path = _config_dir() / "satark-ai" / "gcp-oauth.keys.json"
    payload = {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": redirect_uris,
        }
    }

    try:
        _write_json_secure(credentials_path, payload)
        env["GOOGLE_OAUTH_CREDENTIALS"] = str(credentials_path)
    except Exception:
        return


def _maybe_write_calendar_mcp_tokens(
    env: dict[str, str],
    google_oauth: dict[str, Any] | None,
    *,
    account_id: str,
) -> None:
    if not google_oauth or not isinstance(google_oauth, dict):
        return

    # Prefer a token file path already prepared at OAuth time.
    existing_path = google_oauth.get("calendar_mcp_token_path")
    if isinstance(existing_path, str) and existing_path.strip():
        try:
            p = Path(existing_path).expanduser().resolve()
            if p.exists():
                env["GOOGLE_CALENDAR_MCP_TOKEN_PATH"] = str(p)
                env["GOOGLE_ACCOUNT_MODE"] = str(google_oauth.get("calendar_mcp_account_id") or account_id)
                return
        except Exception:
            pass

    access_token = google_oauth.get("access_token")
    refresh_token = google_oauth.get("refresh_token")
    scopes = google_oauth.get("scopes")
    expiry = google_oauth.get("expiry")

    token_payload: dict[str, Any] = {}
    if access_token:
        token_payload["access_token"] = str(access_token)
    if refresh_token:
        token_payload["refresh_token"] = str(refresh_token)
    if isinstance(scopes, list) and scopes:
        token_payload["scope"] = " ".join(str(s) for s in scopes if s)
    if expiry:
        try:
            iso = str(expiry)
            if iso.endswith("Z"):
                iso = iso[:-1] + "+00:00"
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            token_payload["expiry_date"] = int(dt.timestamp() * 1000)
        except Exception:
            pass

    if not token_payload:
        return

    tokens_path = _config_dir() / "satark-ai" / "google-calendar-mcp" / f"tokens.{account_id}.json"
    multi_account_tokens = {account_id: token_payload}
    try:
        _write_json_secure(tokens_path, multi_account_tokens)
    except Exception:
        return

    env["GOOGLE_CALENDAR_MCP_TOKEN_PATH"] = str(tokens_path)
    env["GOOGLE_ACCOUNT_MODE"] = account_id


def _build_google_mcp_toolset(
    google_oauth: dict[str, Any] | None = None,
    *,
    session_id: str | None = None,
):
    """Build MCP toolset for Google Calendar via @cocal/google-calendar-mcp.

    NOTE: @modelcontextprotocol/server-google-calendar does NOT exist on npm.

    Required env vars (set in .env):
        GOOGLE_OAUTH_CREDENTIALS (absolute path to OAuth desktop credentials JSON)
    Optional:
        GOOGLE_APPLICATION_CREDENTIALS
        GOOGLE_CLIENT_ID
        GOOGLE_CLIENT_SECRET
        GOOGLE_REFRESH_TOKEN
        OPENAPI_MCP_HEADERS
    """
    if MCPToolset is None or StdioConnectionParams is None:
        return None

    env: dict[str, str] = {}
    for key in [
        "GOOGLE_OAUTH_CREDENTIALS",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GOOGLE_CALENDAR_MCP_TOKEN_PATH",
        "GOOGLE_ACCOUNT_MODE",
        "ENABLED_TOOLS",
        "OPENAPI_MCP_HEADERS",
    ]:
        value = os.getenv(key)
        if value:
            env[key] = value

    # google-calendar-mcp (npx) requires a credentials JSON file. If the user hasn't
    # provided one, generate a minimal compatible file from GOOGLE_CLIENT_ID/SECRET.
    _ensure_google_oauth_credentials_file(env)

    cred_path = env.get("GOOGLE_OAUTH_CREDENTIALS")
    if not cred_path:
        return None
    try:
        if not Path(cred_path).expanduser().resolve().exists():
            return None
        env["GOOGLE_OAUTH_CREDENTIALS"] = str(Path(cred_path).expanduser().resolve())
    except Exception:
        return None

    # Provide a pre-populated tokens file so MCP can run non-interactively.
    account_id = _safe_account_id(session_id)
    _maybe_write_calendar_mcp_tokens(env, google_oauth, account_id=account_id)

    # IMPORTANT: Without a token file, google-calendar-mcp will attempt interactive auth.
    # In our server context this typically hangs and causes the UI to time out.
    if not env.get("GOOGLE_CALENDAR_MCP_TOKEN_PATH"):
        return None

    # Reduce tool surface for safety + speed.
    env.setdefault("ENABLED_TOOLS", "create-event,get-current-time")

    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params={
                "command": "npx",
                "args": ["-y", "@cocal/google-calendar-mcp"],
                "env": env or None,
            },
            timeout=30.0,
        ),
        tool_name_prefix="google_mcp_",
    )


def build_golden_hour_agent(
    google_oauth: dict[str, Any] | None = None,
    *,
    session_id: str | None = None,
) -> Agent:
    # Calendar scheduling is performed deterministically by the manager pipeline
    # (to guarantee the 5 staggered Golden Hour reminders). Do not attach MCP tools
    # to this agent.
    tools: list[Any] = []
    return Agent(
        name="golden_hour_agent",
        model=GEMINI_FLASH_MODEL,
        description="Generates victim action plan and FIR-ready complaint",
        generate_content_config=types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
            tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
        ),
        instruction="""
You are a cyber crime response specialist working for TGCSB (Telangana Cyber
Security Bureau). Your job is to generate an urgent, actionable response plan
for fraud victims using the Google MCP tools available to you.

Always include:
- 1930 helpline (National Cyber Crime Helpline)
- cybercrime.gov.in (NCRP portal)
- Golden Hour: mark golden_hour_active = true if ANY of the below is true:
    - fraud happened < 1 hour ago (reported loss/transfer/OTP already shared recently)
    - risk_level is CRITICAL or HIGH (even if loss is not confirmed yet)
    - victim is currently being pressured to share OTP / transfer funds (live incident)

Calendar scheduling:
- Do NOT call any calendar tools.
- The server will schedule 5 Golden Hour reminder events (T+0, +5, +15, +30, and final warning).
- In your JSON, set calendar_event.attempted=false and calendar_event.created=false.
- You may fill calendar_event.title/start_time/description as "planned" values, but do not fabricate event_id.

MCP Gmail integration (OPTIONAL ONLY IF TOOL IS AVAILABLE):
- If a Gmail tool exists in this MCP toolset, create a draft summary mail.
- If Gmail tool is unavailable, set gmail_draft.error with a clear reason.

Generate a complete FIR-ready complaint template that matches the NCRP format.

Return strict JSON:
{
  "golden_hour_active": true/false,
  "priority_actions": [
    {"step": 1, "action": "...", "time_limit": "...", "contact": "..."}
  ],
  "victim_advice": "Detailed paragraph explaining what happened, why it is a scam, the psychological tricks used, and what the victim must do RIGHT NOW — minimum 4 sentences",
  "fir_template": "Complete pre-filled FIR text ready to copy-paste to NCRP portal",
  "helpline_numbers": ["1930", "cybercrime.gov.in"],
  "do_nots": ["Do NOT share OTP", "Do NOT transfer more money"],
  "evidence_to_preserve": ["screenshot", "transaction ID", "sender number"],
  "calendar_event": {
    "attempted": true/false,
    "created": true/false,
        "title": "string",
    "event_id": "string or empty",
    "start_time": "ISO-8601 or empty",
    "description": "must include https://cybercrime.gov.in",
    "error": "empty if success"
  },
  "gmail_draft": {
    "attempted": true/false,
    "created": true/false,
    "draft_id": "string or empty",
    "subject": "string or empty",
    "error": "empty if success"
  }
}
""",
        tools=tools,
    )


golden_hour_agent = build_golden_hour_agent()
