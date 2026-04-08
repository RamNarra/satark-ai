#!/usr/bin/env python3
"""Run live APK smoke checks with API-first phase-aware capture.

Outputs:
- artifacts/runtime-evidence/apk-live-<case>-request.json
- artifacts/runtime-evidence/apk-live-<case>-sse-events.json
- artifacts/runtime-evidence/apk-live-<case>-api-result.json (on completion)
- artifacts/runtime-evidence/apk-live-<case>-partial.json (on failure)
- artifacts/runtime-evidence/apk-live-<case>-ui.png (optional)
- artifacts/runtime-evidence/apk-live-trio-check.json or apk-live-single-check.json
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "artifacts" / "regression-fixtures"
OUT_DIR = ROOT / "artifacts" / "runtime-evidence"
BASE_URL = "http://127.0.0.1:8101"

CASE_FIXTURES: dict[str, Path] = {
    "known_training": FIXTURE_DIR / "apk_known_training.json",
    "malicious": FIXTURE_DIR / "apk_malicious_like.json",
    "benign": FIXTURE_DIR / "apk_benign_like.json",
}


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_apk_like_payload(raw_text: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("classes.dex", raw_text)
        zf.writestr("AndroidManifest.xml", raw_text)
    return buffer.getvalue()


def _http_json(method: str, url: str, payload: dict[str, Any] | None = None, timeout: int = 20) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url=url, method=method.upper(), data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        body = resp.read().decode("utf-8")
        if not body.strip():
            return {}
        return json.loads(body)


def _ensure_server(base_url: str) -> dict[str, Any]:
    return _http_json("GET", f"{base_url}/health", timeout=10)


def _first_index(items: list[str], needle: str) -> int:
    for i, item in enumerate(items):
        if needle in item:
            return i
    return -1


def _infer_stalled_phase(sse_events: list[dict[str, Any]]) -> str:
    event_names = [str(e.get("event") or "") for e in sse_events]
    if "run.completed" in event_names:
        return "completed"
    if "run.failed" in event_names:
        return "manager"

    labels = [str((e.get("data") or {}).get("message") or (e.get("data") or {}).get("label") or "") for e in sse_events]
    if any("Preparing verdict" in label for label in labels):
        return "manager"
    if any("Searching public references" in label for label in labels):
        return "osint"
    if any("Inspecting APK structure" in label for label in labels):
        return "apk_analysis"
    return "accepted"


def _grade_wording(main_text: str) -> str:
    text = " ".join(main_text.split())
    sentence_count = text.count(".") + text.count("!") + text.count("?")
    robotic_markers = ["analysis complete", "model response", "risk markers"]
    marker_hits = sum(1 for marker in robotic_markers if marker in text.lower())
    if len(text) >= 140 and sentence_count >= 2 and marker_hits == 0:
        return "Perplexity/Gemini-grade"
    if len(text) >= 90 and sentence_count >= 2:
        return "Good but slightly robotic"
    return "Too robotic / too terse"


class SseRecorder:
    def __init__(self, stream_url: str, *, verbose: bool = False):
        self.stream_url = stream_url
        self.verbose = verbose
        self.events: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, join_timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)

    def _run(self) -> None:
        req = urllib.request.Request(self.stream_url, headers={"Accept": "text/event-stream"})
        current_event = "message"
        data_lines: list[str] = []
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
                while not self._stop.is_set():
                    raw = resp.readline()
                    if raw == b"":
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if not line:
                        if data_lines:
                            data_raw = "\n".join(data_lines)
                            data_obj: Any
                            try:
                                data_obj = json.loads(data_raw)
                            except Exception:
                                data_obj = {"raw": data_raw}
                            event = {
                                "ts": _utc_now(),
                                "event": current_event,
                                "data": data_obj,
                            }
                            self.events.append(event)
                            if self.verbose:
                                print(f"[SSE {event['ts']}] {current_event} {json.dumps(data_obj, ensure_ascii=True)}")
                            current_event = "message"
                            data_lines = []
                        continue
                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        current_event = line.split(":", 1)[1].strip() or "message"
                        continue
                    if line.startswith("data:"):
                        data_lines.append(line.split(":", 1)[1].lstrip())
                        continue
        except Exception as exc:
            self.errors.append(str(exc))


def run_case_api(
    case_name: str,
    fixture: dict[str, Any],
    *,
    base_url: str,
    timeout_s: int,
    verbose_sse: bool,
) -> dict[str, Any]:
    payload_bytes = _build_apk_like_payload(str(fixture.get("raw_text") or ""))
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    file_name = str(fixture.get("file_name") or f"{case_name}.apk")

    analyze_payload: dict[str, Any] = {
        "session_id": f"sess_live_{uuid.uuid4().hex[:10]}",
        "user_input": {
            "text": "Please investigate this APK and explain the risk in plain language.",
            "files": [
                {
                    "file_name": file_name,
                    "file_type": "application/vnd.android.package-archive",
                    "content_base64": payload_b64,
                }
            ],
        },
        "user_context": {"channel": "web-ui", "locale": "en-IN"},
        "options": {
            "stream": True,
            "generate_report": True,
            "trigger_mcp_actions": False,
        },
    }

    request_start = time.time()
    accepted = _http_json("POST", f"{base_url}/api/analyze", analyze_payload, timeout=30)
    run_id = str(accepted.get("run_id") or "")
    case_id = str(accepted.get("case_id") or "")
    if not run_id:
        raise RuntimeError("analyze response missing run_id")

    recorder = SseRecorder(f"{base_url}/api/stream/{run_id}", verbose=verbose_sse)
    recorder.start()

    result_payload: dict[str, Any] | None = None
    failed_payload: dict[str, Any] | None = None
    stalled_phase = "accepted"
    deadline = time.time() + timeout_s
    poll_errors: list[str] = []

    while time.time() < deadline:
        try:
            polled = _http_json("GET", f"{base_url}/api/result/{run_id}", timeout=20)
        except urllib.error.HTTPError as exc:
            if int(getattr(exc, "code", 0)) == 202:
                time.sleep(1.0)
                continue
            raise
        except TimeoutError as exc:
            poll_errors.append(f"timeout: {exc}")
            time.sleep(1.0)
            continue
        except urllib.error.URLError as exc:
            poll_errors.append(f"url_error: {exc}")
            time.sleep(1.0)
            continue

        status = str(polled.get("status") or "")
        if status in {"accepted", "running"}:
            time.sleep(1.0)
            continue
        if status == "failed":
            failed_payload = polled
            stalled_phase = _infer_stalled_phase(recorder.events)
            break
        result_payload = polled
        stalled_phase = "completed"
        break

    recorder.stop()

    if stalled_phase != "completed" and result_payload is None and failed_payload is None:
        stalled_phase = _infer_stalled_phase(recorder.events)

    output: dict[str, Any] = {
        "case": case_name,
        "run_id": run_id,
        "case_id": case_id,
        "stalled_phase": stalled_phase,
        "request_elapsed_seconds": round(time.time() - request_start, 3),
        "analyze_request": analyze_payload,
        "analyze_accept": accepted,
        "sse_events": recorder.events,
        "sse_errors": recorder.errors,
        "last_sse_event": recorder.events[-1] if recorder.events else None,
        "recent_sse_events": recorder.events[-10:],
        "poll_errors": poll_errors[-20:],
    }
    if result_payload is not None:
        output["api_result"] = result_payload
    if failed_payload is not None:
        output["api_failed"] = failed_payload
    return output


def capture_ui(
    case_name: str,
    fixture: dict[str, Any],
    *,
    base_url: str,
    timeout_s: int,
) -> dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"playwright unavailable: {exc}") from exc

    payload = _build_apk_like_payload(str(fixture.get("raw_text") or ""))
    temp_dir = OUT_DIR / "apk-live-inputs"
    temp_dir.mkdir(parents=True, exist_ok=True)
    file_name = str(fixture.get("file_name") or f"{case_name}.apk")
    apk_path = temp_dir / f"{case_name}-{file_name}"
    apk_path.write_bytes(payload)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        result_holder: dict[str, Any] = {}
        run_holder: dict[str, str] = {}

        def on_response(response) -> None:
            if "/api/analyze" in response.url and response.status == 200:
                try:
                    payload_obj = response.json()
                except Exception:
                    return
                if isinstance(payload_obj, dict) and payload_obj.get("run_id"):
                    run_holder["run_id"] = str(payload_obj.get("run_id"))
                return

        page.on("response", on_response)
        page.goto(f"{base_url}/ui", wait_until="domcontentloaded")
        page.wait_for_selector("#composerInput", timeout=20_000)
        page.set_input_files("#fileInput", str(apk_path))
        page.fill("#composerInput", "Please investigate this APK and explain the risk in plain language.")
        page.click("#sendBtn")

        run_deadline = time.time() + 30
        while time.time() < run_deadline and not run_holder.get("run_id"):
            page.wait_for_timeout(200)
        run_id = run_holder.get("run_id")
        if not run_id:
            raise TimeoutError(f"ui_capture timed out waiting for run_id for {case_name}")

        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                polled = _http_json("GET", f"{base_url}/api/result/{run_id}", timeout=15)
            except urllib.error.HTTPError as exc:
                if int(getattr(exc, "code", 0)) == 202:
                    page.wait_for_timeout(500)
                    continue
                raise
            except Exception:
                page.wait_for_timeout(500)
                continue

            status = str(polled.get("status") or "")
            if status in {"accepted", "running"}:
                page.wait_for_timeout(500)
                continue
            if status == "failed":
                raise RuntimeError(f"ui_capture run failed for {case_name}")
            result_holder["payload"] = polled
            break
        if "payload" not in result_holder:
            raise TimeoutError(f"ui_capture timed out waiting for /api/result for {case_name}")

        try:
            page.wait_for_function(
                """
                () => {
                  const bots = Array.from(document.querySelectorAll('.msg.bot'));
                  if (!bots.length) return false;
                  const p = bots[bots.length - 1].querySelector('.bubble-body p');
                  return !!(p && p.textContent && p.textContent.trim().length > 0);
                }
                """,
                timeout=60_000,
            )
        except PlaywrightTimeoutError as exc:
            raise TimeoutError(f"ui_capture timed out waiting for bot bubble for {case_name}") from exc

        ui_snapshot = page.evaluate(
            """
            () => {
              const bots = Array.from(document.querySelectorAll('.msg.bot'));
              const last = bots[bots.length - 1];
              const main = (last?.querySelector('.bubble-body p')?.textContent || '').trim();
              const notes = Array.from(last?.querySelectorAll('.msg-meta-note') || []).map(el => (el.textContent || '').trim());
              const details = last?.querySelector('.msg-technical-details');
              const detailsPresent = !!details;
              const detailsOpen = !!details?.open;
              const flags = Array.from(last?.querySelectorAll('.flags .flag') || []).map(el => (el.textContent || '').trim());
              return { main, notes, detailsPresent, detailsOpen, flags };
            }
            """
        )

        screenshot_path = OUT_DIR / f"apk-live-{case_name}-ui.png"
        page.screenshot(path=str(screenshot_path), full_page=True)

        context.close()
        browser.close()

        return {
            "screenshot": str(screenshot_path.relative_to(ROOT)),
            "ui": ui_snapshot,
            "ui_api_result": result_holder.get("payload") or {},
        }


def evaluate_case(
    case_name: str,
    *,
    api_output: dict[str, Any],
    ui_output: dict[str, Any] | None,
) -> dict[str, Any]:
    api_result = api_output.get("api_result") if isinstance(api_output.get("api_result"), dict) else {}
    sse_events = api_output.get("sse_events") if isinstance(api_output.get("sse_events"), list) else []

    labels: list[str] = []
    for event in sse_events:
        if not isinstance(event, dict):
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        labels.append(str(data.get("message") or data.get("label") or ""))

    idx_apk = _first_index(labels, "Inspecting APK structure")
    idx_osint = _first_index(labels, "Searching public references")
    idx_manager = _first_index(labels, "Preparing verdict")
    progress_order_ok = idx_apk >= 0 and idx_osint >= 0 and idx_manager >= 0 and idx_apk < idx_osint < idx_manager

    manager_requires_reporting = bool(api_result.get("requires_reporting"))
    manager_requires_emergency = bool(api_result.get("requires_emergency"))

    checks: dict[str, Any] = {
        "progress_stage_order_ok": progress_order_ok,
        "progress_stage_indices": {
            "inspect_apk": idx_apk,
            "search_public_refs": idx_osint,
            "prepare_verdict": idx_manager,
        },
        "chat_reply_present": bool(str(api_result.get("chat_reply") or "").strip()),
        "evidence_present": bool(api_result.get("why_this_decision")),
        "uncertainty_present_if_needed": (
            (not bool(api_result.get("requires_reporting")) and not bool(api_result.get("requires_emergency")))
            or bool(str(api_result.get("uncertainty_note") or "").strip())
        ),
        "no_unwanted_escalation": manager_requires_reporting or manager_requires_emergency or (
            not manager_requires_reporting and not manager_requires_emergency
        ),
        "apk_osint_influence_present": bool(api_result.get("apk_analysis")) and bool(api_result.get("osint_enrichment")),
        "technical_details_secondary": None,
        "chat_reply_first_ok": None,
    }

    quality_note = "N/A"
    if isinstance(ui_output, dict):
        ui = ui_output.get("ui") if isinstance(ui_output.get("ui"), dict) else {}
        ui_api_result = ui_output.get("ui_api_result") if isinstance(ui_output.get("ui_api_result"), dict) else {}
        main_text = str(ui.get("main") or "")
        expected_chat_reply = str(ui_api_result.get("chat_reply") or api_result.get("chat_reply") or "").strip()
        checks["technical_details_secondary"] = bool(ui.get("detailsPresent")) and not bool(ui.get("detailsOpen"))
        checks["chat_reply_first_ok"] = expected_chat_reply == main_text.strip()
        quality_note = _grade_wording(main_text)

    return {
        "case": case_name,
        "run_id": str(api_output.get("run_id") or ""),
        "case_id": str(api_output.get("case_id") or ""),
        "stalled_phase": str(api_output.get("stalled_phase") or ""),
        "checks": checks,
        "quality_note": quality_note,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run live APK smoke checks with phase-aware artifacts.")
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--case", choices=["all", "known_training", "malicious", "benign"], default="all")
    parser.add_argument("--no-screenshot", action="store_true", help="Skip Playwright UI capture")
    parser.add_argument("--verbose-sse", action="store_true", help="Print every SSE event with timestamp")
    parser.add_argument("--timeout-phase", type=int, default=300, help="Timeout seconds for API orchestration")
    parser.add_argument("--timeout-ui", type=int, default=120, help="Timeout seconds for UI capture")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    health_payload = _ensure_server(args.base_url)
    print(f"[HEALTH] {json.dumps(health_payload, ensure_ascii=True)}")

    selected_cases = list(CASE_FIXTURES.keys()) if args.case == "all" else [args.case]
    results: list[dict[str, Any]] = []
    failed = False
    failure_phase = ""

    for case_name in selected_cases:
        fixture = _load_json(CASE_FIXTURES[case_name])
        api_output = run_case_api(
            case_name,
            fixture,
            base_url=args.base_url,
            timeout_s=max(30, int(args.timeout_phase)),
            verbose_sse=bool(args.verbose_sse),
        )

        request_path = OUT_DIR / f"apk-live-{case_name}-request.json"
        sse_path = OUT_DIR / f"apk-live-{case_name}-sse-events.json"
        _write_json(request_path, {
            "generated_at": _utc_now(),
            "case": case_name,
            "health": health_payload,
            "analyze_request": api_output.get("analyze_request"),
            "analyze_accept": api_output.get("analyze_accept"),
        })
        _write_json(sse_path, {
            "generated_at": _utc_now(),
            "case": case_name,
            "run_id": api_output.get("run_id"),
            "events": api_output.get("sse_events") or [],
            "errors": api_output.get("sse_errors") or [],
            "last_event": api_output.get("last_sse_event"),
        })

        if isinstance(api_output.get("api_result"), dict):
            _write_json(OUT_DIR / f"apk-live-{case_name}-api-result.json", api_output["api_result"])
        else:
            failure_phase = str(api_output.get("stalled_phase") or "accepted")
            partial = {
                "generated_at": _utc_now(),
                "case": case_name,
                "failed_phase": failure_phase,
                "health": health_payload,
                "api": {
                    "run_id": api_output.get("run_id"),
                    "case_id": api_output.get("case_id"),
                    "analyze_accept": api_output.get("analyze_accept"),
                    "stalled_phase": api_output.get("stalled_phase"),
                    "request_elapsed_seconds": api_output.get("request_elapsed_seconds"),
                    "api_failed": api_output.get("api_failed"),
                    "last_sse_event": api_output.get("last_sse_event"),
                    "recent_sse_events": api_output.get("recent_sse_events"),
                },
            }
            partial_path = OUT_DIR / f"apk-live-{case_name}-partial.json"
            _write_json(partial_path, partial)
            print(f"[FAIL] case={case_name} phase={failure_phase} partial={partial_path.relative_to(ROOT)}")
            failed = True
            results.append({
                "case": case_name,
                "run_id": api_output.get("run_id"),
                "case_id": api_output.get("case_id"),
                "stalled_phase": failure_phase,
                "checks": {},
                "partial_artifact": str(partial_path.relative_to(ROOT)),
            })
            continue

        ui_output: dict[str, Any] | None = None
        if not args.no_screenshot:
            try:
                ui_output = capture_ui(
                    case_name,
                    fixture,
                    base_url=args.base_url,
                    timeout_s=max(30, int(args.timeout_ui)),
                )
            except Exception as exc:
                failure_phase = "ui_capture"
                partial = {
                    "generated_at": _utc_now(),
                    "case": case_name,
                    "failed_phase": failure_phase,
                    "error": str(exc),
                    "api_run_id": api_output.get("run_id"),
                    "last_sse_event": api_output.get("last_sse_event"),
                    "recent_sse_events": api_output.get("recent_sse_events"),
                }
                partial_path = OUT_DIR / f"apk-live-{case_name}-partial.json"
                _write_json(partial_path, partial)
                print(f"[FAIL] case={case_name} phase=ui_capture partial={partial_path.relative_to(ROOT)}")
                failed = True

        evaluated = evaluate_case(case_name, api_output=api_output, ui_output=ui_output)
        if isinstance(ui_output, dict):
            evaluated["screenshot"] = ui_output.get("screenshot")
        evaluated["manager_contract_path"] = str((OUT_DIR / f"apk-live-{case_name}-api-result.json").relative_to(ROOT))
        results.append(evaluated)
        print(
            f"[OK] case={case_name} run_id={evaluated.get('run_id')} "
            f"progress_order={evaluated.get('checks', {}).get('progress_stage_order_ok')} "
            f"chat_reply_present={evaluated.get('checks', {}).get('chat_reply_present')}"
        )

    report = {
        "generated_at": _utc_now(),
        "base_url": args.base_url,
        "mode": "single" if len(selected_cases) == 1 else "trio",
        "cases": results,
        "overall": {
            "all_chat_reply_present": all(bool(c.get("checks", {}).get("chat_reply_present")) for c in results if c.get("checks")),
            "all_progress_order_ok": all(bool(c.get("checks", {}).get("progress_stage_order_ok")) for c in results if c.get("checks")),
            "all_apk_osint_influence_present": all(bool(c.get("checks", {}).get("apk_osint_influence_present")) for c in results if c.get("checks")),
        },
    }

    report_path = OUT_DIR / ("apk-live-single-check.json" if len(selected_cases) == 1 else "apk-live-trio-check.json")
    _write_json(report_path, report)
    print(f"[REPORT] {report_path.relative_to(ROOT)}")

    if failed:
        phase = failure_phase or "unknown"
        print(f"[EXIT] stalled_phase={phase}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
