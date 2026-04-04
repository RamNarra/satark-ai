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

REQUIRED_MCP_REFRESH = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REFRESH_TOKEN",
]

REQUIRED_MCP_OAUTH_FILE = "GOOGLE_OAUTH_CREDENTIALS"

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
            ["npm", "view", "@cocal/google-calendar-mcp", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"[OK] @cocal/google-calendar-mcp available (latest: {result.stdout.strip()})")
            return True
        print("[WARN] Could not verify @cocal/google-calendar-mcp via npm view.")
        return True
    except Exception:
        print("[WARN] npm view check skipped (network or npm issue).")
        return True


def _check_mcp_auth_mode() -> bool:
    oauth_file = os.getenv(REQUIRED_MCP_OAUTH_FILE, "").strip()
    oauth_ok = bool(oauth_file)
    refresh_checks = [_print_status(key, required=True) for key in REQUIRED_MCP_REFRESH]
    refresh_ok = all(refresh_checks)

    oauth_marker = "OK" if oauth_ok else "MISSING"
    print(f"[{oauth_marker}] {REQUIRED_MCP_OAUTH_FILE} (required OR use refresh-token triplet)")
    if oauth_ok and not os.path.exists(oauth_file):
        print(f"[WARN] {REQUIRED_MCP_OAUTH_FILE} path does not exist: {oauth_file}")

    if oauth_ok or refresh_ok:
        return True

    print("[FAIL] Configure either GOOGLE_OAUTH_CREDENTIALS or all refresh-token variables.")
    return False


def main() -> int:
    load_dotenv()

    print("SATARK MCP preflight")
    print("--------------------")

    core_checks = [_print_status(key, required=True) for key in REQUIRED_CORE]
    core_ok = all(core_checks)
    mcp_ok = _check_mcp_auth_mode()

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
