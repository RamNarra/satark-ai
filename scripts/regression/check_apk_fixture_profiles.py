#!/usr/bin/env python3
"""Deterministic APK profile regression checks using local fixtures."""

from __future__ import annotations

import json
import io
import zipfile
from pathlib import Path

from agents.apk_analyzer.agent import build_apk_analysis_contract, run_static_analysis


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "artifacts" / "regression-fixtures"

RISK_RANK = {
    "SAFE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _load_fixture(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _assert_risk_not_above(actual: str, ceiling: str) -> None:
    if RISK_RANK.get(actual, 0) > RISK_RANK.get(ceiling, 0):
        raise AssertionError(f"Risk level {actual} exceeds ceiling {ceiling}")


def _assert_risk_at_least(actual: str, floor: str) -> None:
    if RISK_RANK.get(actual, 0) < RISK_RANK.get(floor, 0):
        raise AssertionError(f"Risk level {actual} is below expected floor {floor}")


def run_fixture(path: Path) -> None:
    fixture = _load_fixture(path)
    file_name = fixture["file_name"]
    payload = _build_apk_like_payload(fixture["raw_text"])
    expected = fixture["expect"]

    static = run_static_analysis(payload, filename=file_name)
    contract = build_apk_analysis_contract(static, filename=file_name)

    if "is_malicious" in expected and bool(contract.get("is_malicious")) != bool(expected["is_malicious"]):
        raise AssertionError(
            f"{fixture['name']}: expected is_malicious={expected['is_malicious']} got {contract.get('is_malicious')}"
        )

    likely_known_project = bool(
        (contract.get("identity_assessment") or {}).get("likely_known_project")
    )
    if "likely_known_project" in expected and likely_known_project != bool(expected["likely_known_project"]):
        raise AssertionError(
            f"{fixture['name']}: expected likely_known_project={expected['likely_known_project']} got {likely_known_project}"
        )

    risk = str(contract.get("risk_level") or "LOW").upper()
    if "risk_not_above" in expected:
        _assert_risk_not_above(risk, str(expected["risk_not_above"]).upper())
    if "risk_at_least" in expected:
        _assert_risk_at_least(risk, str(expected["risk_at_least"]).upper())

    if "must_include_dangerous" in expected:
        dangerous = set(contract.get("permissions", {}).get("dangerous", []))
        dangerous.update(contract.get("dangerous_permissions", []))
        for perm in expected["must_include_dangerous"]:
            if perm not in dangerous:
                raise AssertionError(f"{fixture['name']}: missing dangerous permission {perm}")

    print(
        f"[OK] {fixture['name']} -> risk={contract.get('risk_level')} "
        f"malicious={contract.get('is_malicious')} known={likely_known_project}"
    )


def _build_apk_like_payload(raw_text: str) -> bytes:
    """Create a minimal ZIP payload so analyzer can inspect APK-like content."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("classes.dex", raw_text)
        zf.writestr("AndroidManifest.xml", raw_text)
    return buffer.getvalue()


def main() -> int:
    fixtures = [
        FIXTURE_DIR / "apk_known_training.json",
        FIXTURE_DIR / "apk_malicious_like.json",
        FIXTURE_DIR / "apk_benign_like.json",
    ]

    missing = [str(p) for p in fixtures if not p.exists()]
    if missing:
        raise FileNotFoundError(f"Missing fixtures: {', '.join(missing)}")

    for fixture_path in fixtures:
        run_fixture(fixture_path)

    print("APK fixture profile regression checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
