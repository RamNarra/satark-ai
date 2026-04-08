from __future__ import annotations

import os
from typing import Any

from satark_mcp.runtime import (
    McpServerSpec,
    call_mcp_tool,
    choose_tool_name,
    list_mcp_tools,
    open_stdio_session,
    parse_json_list_env,
)


def _server_spec_from_env(prefix: str) -> McpServerSpec | None:
    command = os.getenv(f"{prefix}_MCP_COMMAND", "").strip()
    if not command:
        return None
    args = parse_json_list_env(f"{prefix}_MCP_ARGS") or []
    timeout_s = float(os.getenv(f"{prefix}_MCP_TIMEOUT_S", "15") or 15)
    return McpServerSpec(command=command, args=args, env=None, timeout_s=timeout_s)


def _build_task_args(schema: dict[str, Any] | None, task: dict[str, Any]) -> dict[str, Any]:
    input_schema = schema or {}
    props = input_schema.get("properties") if isinstance(input_schema, dict) else None
    if isinstance(props, dict) and "task" in props:
        return {"task": task}
    return dict(task)


async def sync_tasks(tasks: list[dict]) -> dict:
    if not tasks:
        return {"tool": "tasks_mcp", "status": "ok", "synced": 0, "tasks": []}

    spec = _server_spec_from_env("SATARK_TASKS")
    if spec is None:
        return {
            "tool": "tasks_mcp",
            "status": "not_configured",
            "synced": 0,
            "error": "Set SATARK_TASKS_MCP_COMMAND and SATARK_TASKS_MCP_ARGS (JSON list) to enable",
            "tasks": tasks,
        }

    explicit_tool = os.getenv("SATARK_TASKS_MCP_TOOL", "").strip()

    try:
        session = await open_stdio_session(spec)
        tools = await list_mcp_tools(session)
        tool_names = [str(t.get("name") or "") for t in tools]
        tool_name = choose_tool_name(
            tool_names,
            prefer=[explicit_tool] if explicit_tool else None,
            require_all_substrings=["task"],
        )
        if not tool_name:
            return {
                "tool": "tasks_mcp",
                "status": "error",
                "synced": 0,
                "error": "No tools found on tasks MCP server",
                "available_tools": tool_names,
                "tasks": tasks,
            }

        tool_def = next((t for t in tools if t.get("name") == tool_name), None) or {}
        tool_schema = tool_def.get("inputSchema") if isinstance(tool_def, dict) else None

        results: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for task in tasks:
            try:
                resp = await call_mcp_tool(
                    session,
                    tool_name,
                    _build_task_args(tool_schema if isinstance(tool_schema, dict) else None, task),
                )
                results.append({"task": task, "result": resp})
            except Exception as exc:
                errors.append({"task": task, "error": str(exc)})

        return {
            "tool": "tasks_mcp",
            "status": "ok" if not errors else "partial",
            "synced": len(results),
            "errors": errors,
            "tool_name": tool_name,
            "tasks": tasks,
            "results": results,
        }
    except Exception as exc:
        return {
            "tool": "tasks_mcp",
            "status": "error",
            "synced": 0,
            "error": str(exc),
            "tasks": tasks,
        }
