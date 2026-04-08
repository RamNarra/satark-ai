from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable

from mcp import ClientSession
from mcp import StdioServerParameters

try:
    from google.adk.tools.mcp_tool.mcp_session_manager import MCPSessionManager
    from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
except Exception:  # pragma: no cover
    MCPSessionManager = None  # type: ignore
    StdioConnectionParams = None  # type: ignore


@dataclass(frozen=True)
class McpServerSpec:
    command: str
    args: list[str]
    env: dict[str, str] | None = None
    timeout_s: float = 15.0


def _compact(obj: Any, limit: int = 2000) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=True, default=str)
    except Exception:
        text = str(obj)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def parse_json_list_env(name: str) -> list[str] | None:
    raw = os.getenv(name)
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
            return list(parsed)
    except Exception:
        return None
    return None


def choose_tool_name(
    tool_names: Iterable[str],
    *,
    prefer: list[str] | None = None,
    require_all_substrings: list[str] | None = None,
) -> str | None:
    names = [n for n in tool_names if isinstance(n, str) and n.strip()]
    if not names:
        return None

    lowered = [(n, n.lower()) for n in names]

    if prefer:
        for wanted in prefer:
            wanted_l = wanted.lower()
            for original, lowered_name in lowered:
                if lowered_name == wanted_l:
                    return original

    if require_all_substrings:
        req = [s.lower() for s in require_all_substrings if s.strip()]
        candidates = [orig for orig, low in lowered if all(s in low for s in req)]
        if candidates:
            return candidates[0]

    return names[0]


async def open_stdio_session(spec: McpServerSpec) -> ClientSession:
    if MCPSessionManager is None or StdioConnectionParams is None:
        raise RuntimeError(
            "google-adk MCP runtime is unavailable (missing google.adk.tools.mcp_tool)."
        )

    server_params = StdioServerParameters(
        command=spec.command,
        args=spec.args,
        env=spec.env,
    )

    session_manager = MCPSessionManager(
        connection_params=StdioConnectionParams(server_params=server_params, timeout=spec.timeout_s)
    )

    # NOTE: Session manager pools sessions; we intentionally do not close it here.
    return await session_manager.create_session()


async def list_mcp_tools(session: ClientSession) -> list[dict[str, Any]]:
    result = await session.list_tools()
    tools = []
    for tool in getattr(result, "tools", []) or []:
        try:
            tools.append(tool.model_dump(mode="json", exclude_none=True))
        except Exception:
            tools.append({"name": getattr(tool, "name", ""), "raw": _compact(tool)})
    return tools


async def call_mcp_tool(session: ClientSession, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = await session.call_tool(tool_name, arguments=arguments)
    try:
        return response.model_dump(mode="json", exclude_none=True)
    except Exception:
        return {"tool": tool_name, "raw": _compact(response)}
