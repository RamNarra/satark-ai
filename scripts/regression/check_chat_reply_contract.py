#!/usr/bin/env python3
"""Regression guard for SATARK chat_reply-first tone contract.

Pass criteria (from live evidence report):
- preventive_sms and informational_apk cases exist.
- both have non-empty chat_reply.
- chat_reply is not collapsed into summary text.
- both stay non-urgent (no reporting/emergency/financial blocking).
- both include at least 3 recommended actions.
- UI proof confirms chat bubble uses chat_reply first.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = ROOT / "artifacts" / "runtime-evidence" / "tone-live-check.json"


class CheckError(Exception):
    pass


def _load_report() -> dict:
    if not REPORT_PATH.exists():
        raise CheckError(
            f"Missing evidence report: {REPORT_PATH}. "
            "Run the tone live-check flow first."
        )
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CheckError("tone-live-check.json must contain a top-level JSON object")
    return payload


def _assert_case(cases: dict, case_name: str) -> list[str]:
    data = cases.get(case_name)
    if not isinstance(data, dict):
        return [f"{case_name}: missing or invalid case object"]

    chat_reply = str(data.get("chat_reply") or "").strip()
    summary = str(data.get("summary") or "").strip()
    reporting = bool(data.get("requires_reporting"))
    emergency = bool(data.get("requires_emergency"))
    financial = bool(data.get("requires_financial_blocking"))
    actions_count = int(data.get("recommended_actions_count") or 0)

    failures: list[str] = []
    if not chat_reply:
        failures.append(f"{case_name}: chat_reply is empty")
    if chat_reply and summary and chat_reply == summary:
        failures.append(f"{case_name}: chat_reply equals summary (tone likely flattened)")
    if reporting:
        failures.append(f"{case_name}: requires_reporting expected False, got True")
    if emergency:
        failures.append(f"{case_name}: requires_emergency expected False, got True")
    if financial:
        failures.append(f"{case_name}: requires_financial_blocking expected False, got True")
    if actions_count < 3:
        failures.append(f"{case_name}: recommended_actions_count expected >= 3, got {actions_count}")

    return failures


def main() -> int:
    report = _load_report()
    cases = report.get("cases")
    if not isinstance(cases, dict):
        raise CheckError("tone-live-check.json missing object: cases")

    failures: list[str] = []
    failures.extend(_assert_case(cases, "preventive_sms"))
    failures.extend(_assert_case(cases, "informational_apk"))

    ui = report.get("ui_chat_reply_first")
    if not isinstance(ui, dict):
        failures.append("ui_chat_reply_first: missing object")
    elif not bool(ui.get("passed")):
        failures.append("ui_chat_reply_first: expected passed=true")

    if failures:
        print("CHAT-REPLY CONTRACT REGRESSION CHECK: FAILED")
        for item in failures:
            print(f"- {item}")
        return 1

    print("CHAT-REPLY CONTRACT REGRESSION CHECK: PASSED")
    print("- preventive_sms: chat_reply preserved, non-urgent")
    print("- informational_apk: chat_reply preserved, non-urgent")
    print("- ui_chat_reply_first: main bubble renders chat_reply")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckError as exc:
        print(f"CHAT-REPLY CONTRACT REGRESSION CHECK: FAILED\n- {exc}")
        raise SystemExit(1)
