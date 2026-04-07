#!/usr/bin/env python3
"""Simple regression guard for SATARK calm-vs-urgent behavior.

Pass criteria:
- prevented_scam: requires_reporting=False and requires_emergency=False
- money_lost: requires_reporting=True and requires_emergency=True
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "artifacts" / "regression-fixtures"


def load_result(name: str) -> dict:
    path = FIXTURE_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing fixture: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"Invalid fixture format in {path}: missing result object")
    return result


def assert_case(name: str, *, reporting: bool, emergency: bool) -> list[str]:
    result = load_result(name)
    got_reporting = bool(result.get("requires_reporting"))
    got_emergency = bool(result.get("requires_emergency"))

    failures: list[str] = []
    if got_reporting != reporting:
        failures.append(
            f"{name}: requires_reporting expected {reporting} but got {got_reporting}"
        )
    if got_emergency != emergency:
        failures.append(
            f"{name}: requires_emergency expected {emergency} but got {got_emergency}"
        )
    return failures


def main() -> int:
    failures: list[str] = []
    failures.extend(assert_case("prevented_scam", reporting=False, emergency=False))
    failures.extend(assert_case("money_lost", reporting=True, emergency=True))

    if failures:
        print("CALM-VS-URGENT REGRESSION CHECK: FAILED")
        for item in failures:
            print(f"- {item}")
        return 1

    print("CALM-VS-URGENT REGRESSION CHECK: PASSED")
    print("- prevented_scam => no reporting/emergency")
    print("- money_lost => reporting + emergency")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
