#!/usr/bin/env python3
"""Regression guard for clarification follow-up hydration + UI chip behavior."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "artifacts" / "runtime-evidence" / "clarification-live-check.json"


class CheckError(Exception):
    pass


def _load_report() -> dict:
    if not REPORT_PATH.exists():
        raise CheckError(
            f"Missing evidence report: {REPORT_PATH}. "
            "Run scripts/regression/run_live_clarification_followup_check.py first."
        )
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CheckError("clarification-live-check.json must be a JSON object")
    return payload


def main() -> int:
    report = _load_report()
    checks = report.get("checks")
    if not isinstance(checks, dict):
        raise CheckError("clarification-live-check.json missing object: checks")

    required = [
        "ui_clarification_found",
        "ui_no_synthetic_user_bubble",
        "ui_pending_in_same_card_only",
        "ui_refresh_no_stale_clarification",
        "api_followup_empty_files_sent",
        "api_followup_empty_files_resolved",
        "api_no_insufficient_info_fallback",
        "api_legacy_fallback_stage_not_used",
        "payload_diff_captures_followup_contract",
    ]

    failures: list[str] = []
    for key in required:
        if key not in checks:
            failures.append(f"missing check: {key}")
            continue
        if not bool(checks.get(key)):
            failures.append(f"{key}: expected true, got false")

    if failures:
        print("CLARIFICATION FOLLOW-UP CONTRACT CHECK: FAILED")
        for item in failures:
            print(f"- {item}")
        print(f"- report: {REPORT_PATH}")
        return 1

    print("CLARIFICATION FOLLOW-UP CONTRACT CHECK: PASSED")
    print("- UI keeps clarification in assistant card without synthetic user bubble")
    print("- Empty-files follow-up resolves via backend hydration without insufficient-info fallback")
    print("- Pre/post payload diff captures follow-up evidence-carry contract")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckError as exc:
        print(f"CLARIFICATION FOLLOW-UP CONTRACT CHECK: FAILED\\n- {exc}")
        raise SystemExit(1)
