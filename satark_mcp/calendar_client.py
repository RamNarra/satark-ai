from __future__ import annotations

import os
import shutil
from typing import Any

from satark_mcp.runtime import (
    McpServerSpec,
    call_mcp_tool,
    choose_tool_name,
    list_mcp_tools,
    open_stdio_session,
    parse_json_list_env,
)


_AUTH_OAUTH_FILE = "GOOGLE_OAUTH_CREDENTIALS"
_AUTH_REFRESH_VARS = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REFRESH_TOKEN",
]


def _calendar_env() -> dict[str, str] | None:
    env: dict[str, str] = {}
    for key in [
        "GOOGLE_OAUTH_CREDENTIALS",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GOOGLE_REFRESH_TOKEN",
        "OPENAPI_MCP_HEADERS",
        "GOOGLE_CALENDAR_ID",
        "SATARK_CALENDAR_TIMEZONE",
    ]:
        value = os.getenv(key)
        if value:
            env[key] = value
    return env or None


def _auth_configured() -> bool:
    if os.getenv(_AUTH_OAUTH_FILE, "").strip():
        return True
    return all(os.getenv(k, "").strip() for k in _AUTH_REFRESH_VARS)


def _build_event_args(tool_schema: dict[str, Any] | None, event: dict[str, Any]) -> dict[str, Any]:
    tz = str(
        event.get("timezone")
        or os.getenv("SATARK_CALENDAR_TIMEZONE")
        or os.getenv("TZ")
        or "UTC"
    )
    calendar_id = str(os.getenv("GOOGLE_CALENDAR_ID", "primary"))

    title = str(event.get("title") or event.get("summary") or "SATARK Task")
    description = str(event.get("description") or "")
    start = str(event.get("start") or event.get("start_time") or "")
    end = str(event.get("end") or event.get("end_time") or "")

    google_event = {
        "summary": title,
        "description": description,
        "start": {"dateTime": start, "timeZone": tz},
        "end": {"dateTime": end, "timeZone": tz},
        "attendees": event.get("attendees") or [],
        "reminders": {
            "useDefault": False,
            "overrides": [{"method": "popup", "minutes": 10}],
        },
    }

    input_schema = tool_schema or {}
    props = input_schema.get("properties") if isinstance(input_schema, dict) else None
    if isinstance(props, dict) and "event" in props:
        args: dict[str, Any] = {"event": google_event}
    else:
        args = dict(google_event)

    if isinstance(props, dict):
        if "calendarId" in props:
            args.setdefault("calendarId", calendar_id)
        elif "calendar_id" in props:
            args.setdefault("calendar_id", calendar_id)
        elif "calendar" in props:
            args.setdefault("calendar", calendar_id)
    else:
        args.setdefault("calendarId", calendar_id)

    return args


async def create_calendar_events(events: list[dict]) -> dict:
    if not events:
        return {"tool": "calendar_mcp", "status": "ok", "created": 0, "events": []}

    command = os.getenv("SATARK_CALENDAR_MCP_COMMAND", "npx").strip() or "npx"
    args = parse_json_list_env("SATARK_CALENDAR_MCP_ARGS") or ["-y", "@cocal/google-calendar-mcp"]

    if command == "npx" and not shutil.which("npx"):
        return {
            "tool": "calendar_mcp",
            "status": "not_configured",
            "created": 0,
            "error": "npx is not available (install Node.js) to run MCP stdio servers",
            "events": events,
        }

    if not _auth_configured():
        return {
            "tool": "calendar_mcp",
            "status": "not_configured",
            "created": 0,
            "error": (
                "Missing Google MCP auth. Set GOOGLE_OAUTH_CREDENTIALS or "
                "GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REFRESH_TOKEN."
            ),
            "events": events,
        }

    try:
        session = await open_stdio_session(
            McpServerSpec(command=command, args=args, env=_calendar_env(), timeout_s=30.0)
        )

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
                "tool": "calendar_mcp",
                "status": "error",
                "created": 0,
                "error": "No MCP tools found on calendar server",
                "available_tools": tool_names,
                "events": events,
            }

        tool_def = next((t for t in tools if t.get("name") == tool_name), None) or {}
        tool_schema = tool_def.get("inputSchema") if isinstance(tool_def, dict) else None

        created: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for ev in events:
            try:
                args_for_tool = _build_event_args(tool_schema if isinstance(tool_schema, dict) else None, ev)
                resp = await call_mcp_tool(session, tool_name, args_for_tool)
                created.append({"event": ev, "result": resp})
            except Exception as exc:
                errors.append({"event": ev, "error": str(exc)})

        return {
            "tool": "calendar_mcp",
            "status": "ok" if not errors else "partial",
            "created": len(created),
            "errors": errors,
            "tool_name": tool_name,
            "events": events,
            "results": created,
        }

    except Exception as exc:
        return {
            "tool": "calendar_mcp",
            "status": "error",
            "created": 0,
            "error": str(exc),
            "events": events,
        }
