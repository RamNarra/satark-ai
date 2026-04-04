#!/usr/bin/env python3
"""Preflight check for SATARK Google MCP auth setup.

Run this before demos/commits to avoid runtime failures from missing auth vars.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from dotenv import load_dotenv


REQUIRED_CORE = [
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
]

REQUIRED_MCP = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REFRESH_TOKEN",
]

OPTIONAL = [
    "OPENAPI_MCP_HEADERS",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CALENDAR_ID",
    "SATARK_CALENDAR_TIMEZONE",
]


def _is_set(name: str) -> bool:
    value = os.getenv(name, "")
    return bool(value.strip())


def _print_status(name: str, required: bool = False) -> bool:
    ok = _is_set(name)
    marker = "OK" if ok else "MISSING"
    label = "required" if required else "optional"
    print(f"[{marker}] {name} ({label})")
    return ok


def _check_node_tools() -> bool:
    npx = shutil.which("npx")
    if not npx:
        print("[MISSING] npx is not available. Install Node.js to run MCP stdio servers.")
        return False

    print(f"[OK] npx found at: {npx}")

    try:
        result = subprocess.run(
            ["npm", "view", "@modelcontextprotocol/server-google", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"[OK] @modelcontextprotocol/server-google available (latest: {result.stdout.strip()})")
            return True
        print("[WARN] Could not verify @modelcontextprotocol/server-google via npm view.")
        return True
    except Exception:
        print("[WARN] npm view check skipped (network or npm issue).")
        return True


def main() -> int:
    load_dotenv()

    print("SATARK MCP preflight")
    print("--------------------")

    core_checks = [_print_status(key, required=True) for key in REQUIRED_CORE]
    mcp_checks = [_print_status(key, required=True) for key in REQUIRED_MCP]
    core_ok = all(core_checks)
    mcp_ok = all(mcp_checks)

    for key in OPTIONAL:
        _print_status(key, required=False)

    node_ok = _check_node_tools()

    if core_ok and mcp_ok and node_ok:
        print("\nPASS: MCP auth preflight looks good.")
        return 0

    print("\nFAIL: Missing required setup for MCP runtime.")
    print("Copy .env.example to .env and fill missing required values.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
