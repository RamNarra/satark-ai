#!/usr/bin/env python3
"""Live clarification regression runner.

Runs one real browser clarification flow, captures payloads/trace/screenshots,
then runs an API follow-up with empty files to verify session hydration.
Also writes a reconstructed pre-patch vs post-patch payload diff artifact.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "artifacts" / "runtime-evidence"
DEFAULT_BASE_URL = "http://127.0.0.1:8101"

REPORT_PATH = OUT_DIR / "clarification-live-check.json"
POST_PAYLOAD_PATH = OUT_DIR / "clarification-followup-payload-postpatch.json"
PRE_PAYLOAD_PATH = OUT_DIR / "clarification-followup-payload-prepatch-reconstructed.json"
DIFF_PAYLOAD_PATH = OUT_DIR / "clarification-followup-payload-diff.json"
TRACE_PATH = OUT_DIR / "clarification-flow-trace.zip"
SCREENSHOT_PENDING_PATH = OUT_DIR / "clarification-flow-pending.png"
SCREENSHOT_FINAL_PATH = OUT_DIR / "clarification-flow-final.png"


def _utc_now() -> str:
	return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _http_json(method: str, url: str, payload: dict[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
	data = None
	headers = {"Accept": "application/json"}
	if payload is not None:
		data = json.dumps(payload).encode("utf-8")
		headers["Content-Type"] = "application/json"
	req = urllib.request.Request(url=url, method=method.upper(), data=data, headers=headers)
	with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
		body = resp.read().decode("utf-8")
		return json.loads(body) if body.strip() else {}


def _poll_result(base_url: str, run_id: str, timeout_s: int = 180) -> dict[str, Any]:
	deadline = time.time() + max(10, int(timeout_s))
	while time.time() < deadline:
		try:
			payload = _http_json("GET", f"{base_url}/api/result/{run_id}", timeout=20)
		except urllib.error.HTTPError as exc:
			if int(getattr(exc, "code", 0)) == 202:
				time.sleep(0.5)
				continue
			raise
		status = str(payload.get("status") or "")
		if status in {"accepted", "running"}:
			time.sleep(0.5)
			continue
		return payload
	raise TimeoutError(f"Timed out waiting for /api/result/{run_id}")


def _sanitize_payload(payload: dict[str, Any]) -> dict[str, Any]:
	obj = copy.deepcopy(payload)
	user_input = obj.get("user_input") if isinstance(obj.get("user_input"), dict) else {}
	files = user_input.get("files") if isinstance(user_input.get("files"), list) else []
	for item in files:
		if not isinstance(item, dict):
			continue
		b64 = str(item.get("content_base64") or "")
		if b64:
			item["content_base64"] = f"<base64:len={len(b64)}>"
	return obj


def _json_diff(pre: Any, post: Any, path: str = "$") -> list[dict[str, Any]]:
	diffs: list[dict[str, Any]] = []
	if isinstance(pre, dict) and isinstance(post, dict):
		pre_keys = set(pre.keys())
		post_keys = set(post.keys())
		for k in sorted(pre_keys - post_keys):
			diffs.append({"op": "removed", "path": f"{path}.{k}", "before": pre[k]})
		for k in sorted(post_keys - pre_keys):
			diffs.append({"op": "added", "path": f"{path}.{k}", "after": post[k]})
		for k in sorted(pre_keys & post_keys):
			diffs.extend(_json_diff(pre[k], post[k], f"{path}.{k}"))
		return diffs

	if isinstance(pre, list) and isinstance(post, list):
		if pre != post:
			diffs.append({"op": "changed", "path": path, "before": pre, "after": post})
		return diffs

	if pre != post:
		diffs.append({"op": "changed", "path": path, "before": pre, "after": post})
	return diffs


def _contains_insufficient_language(payload: dict[str, Any]) -> bool:
	corpus = "\n".join(
		[
			str(payload.get("summary") or ""),
			str(payload.get("chat_reply") or ""),
			str(payload.get("conversational_reply") or ""),
			str(payload.get("verdict") or ""),
		]
	).lower()
	needles = [
		"full content of the sms",
		"provide the full content",
		"not enough information",
		"insufficient information",
		"unable to determine",
	]
	return any(n in corpus for n in needles)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _ensure_health(base_url: str) -> dict[str, Any]:
	return _http_json("GET", f"{base_url}/health", timeout=10)


def _build_tiny_png(path: Path) -> None:
	png_b64 = (
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
	)
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_bytes(base64.b64decode(png_b64))


def _run_browser_flow(base_url: str, timeout_s: int) -> dict[str, Any]:
	try:
		from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
		from playwright.sync_api import sync_playwright
	except Exception as exc:  # pragma: no cover
		raise RuntimeError(f"Playwright unavailable: {exc}") from exc

	temp_png = OUT_DIR / "clarification-flow-input.png"
	_build_tiny_png(temp_png)

	prompts = [
		"I got this suspicious screenshot. I am not sure whether I clicked any link. Is this a scam?",
		"Please verify this screenshot. I am unsure what happened and need safe next steps.",
		"I received this fraud-looking message screenshot. Can you assess the risk?",
	]

	with sync_playwright() as p:
		browser = p.chromium.launch(headless=True)
		context = browser.new_context(viewport={"width": 1440, "height": 960})
		context.tracing.start(screenshots=True, snapshots=True, sources=True)
		page = context.new_page()

		analyze_payloads: list[dict[str, Any]] = []
		analyze_responses: list[dict[str, Any]] = []

		def on_request(req) -> None:
			if not req.url.endswith("/api/analyze"):
				return
			if req.method.upper() != "POST":
				return
			try:
				payload = req.post_data_json
			except Exception:
				return
			if isinstance(payload, dict):
				analyze_payloads.append(payload)

		def on_response(resp) -> None:
			if not resp.url.endswith("/api/analyze") or resp.status != 200:
				return
			try:
				data = resp.json()
			except Exception:
				return
			if isinstance(data, dict):
				analyze_responses.append(data)

		page.on("request", on_request)
		page.on("response", on_response)

		clarification_msg_id = ""
		clarification_prompt = ""

		for prompt in prompts:
			page.goto(f"{base_url}/ui", wait_until="domcontentloaded")
			page.wait_for_selector("#composerInput", timeout=20_000)
			page.fill("#composerInput", prompt)
			page.set_input_files("#fileInput", str(temp_png))
			page.click("#sendBtn")

			try:
				page.wait_for_selector(
					".msg.bot .clarification-wrap .clarification-btn:not([disabled])",
					timeout=max(20_000, timeout_s * 1000),
				)
				clarification_prompt = prompt
				break
			except PlaywrightTimeoutError:
				continue

		if not clarification_prompt:
			raise TimeoutError("No clarification UI appeared in browser flow")

		info = page.evaluate(
			"""
			() => {
			  const btn = document.querySelector('.msg.bot .clarification-wrap .clarification-btn:not([disabled])');
			  const msg = btn ? btn.closest('.msg.bot') : null;
			  return {
				messageId: msg?.dataset?.messageId || '',
				userCount: document.querySelectorAll('.msg.user').length,
				optionLabel: (btn?.textContent || '').trim(),
			  };
			}
			"""
		)
		clarification_msg_id = str(info.get("messageId") or "").strip()
		if not clarification_msg_id:
			raise RuntimeError("Could not resolve clarification assistant message id")

		user_count_before = int(info.get("userCount") or 0)
		analyze_count_before_click = len(analyze_payloads)

		page.click(f".msg.bot[data-message-id='{clarification_msg_id}'] .clarification-btn:not([disabled])")
		page.wait_for_selector(
			f".msg.bot[data-message-id='{clarification_msg_id}'] .clarification-pending",
			timeout=15_000,
		)
		pending_seen_in_target = True
		page.screenshot(path=str(SCREENSHOT_PENDING_PATH), full_page=True)

		pending_state = page.evaluate(
			"""
			(mid) => {
			  const own = !!document.querySelector(`.msg.bot[data-message-id='${mid}'] .clarification-pending`);
			  const total = document.querySelectorAll('.clarification-pending').length;
			  const outside = own ? Math.max(0, total - 1) : total;
			  return { own, total, outside };
			}
			""",
			clarification_msg_id,
		)
		user_count_after_click = int(
			page.evaluate("() => document.querySelectorAll('.msg.user').length")
		)

		deadline = time.time() + 20
		while time.time() < deadline and len(analyze_payloads) <= analyze_count_before_click:
			page.wait_for_timeout(200)

		if len(analyze_payloads) <= analyze_count_before_click:
			raise TimeoutError("Follow-up /api/analyze request not captured after chip click")

		followup_payload = analyze_payloads[analyze_count_before_click]
		initial_payload = analyze_payloads[0]

		page.wait_for_function(
			"""
			(mid) => !document.querySelector(`.msg.bot[data-message-id='${mid}'] .clarification-pending`)
			""",
			arg=clarification_msg_id,
			timeout=max(20_000, timeout_s * 1000),
		)
		page.screenshot(path=str(SCREENSHOT_FINAL_PATH), full_page=True)

		user_count_after_final = int(
			page.evaluate("() => document.querySelectorAll('.msg.user').length")
		)

		page.reload(wait_until="domcontentloaded")
		page.wait_for_selector("#thread", timeout=20_000)
		refreshed = page.evaluate(
			"""
			() => ({
				clarificationButtons: document.querySelectorAll('.clarification-wrap .clarification-btn').length,
				userCount: document.querySelectorAll('.msg.user').length,
			})
			"""
		)

		context.tracing.stop(path=str(TRACE_PATH))
		context.close()
		browser.close()

		return {
			"prompt": clarification_prompt,
			"clarification_message_id": clarification_msg_id,
			"user_count_before_click": user_count_before,
			"user_count_after_click": user_count_after_click,
			"user_count_after_final": user_count_after_final,
			"pending_in_same_card": bool(pending_state.get("own")),
			"pending_total_count": int(pending_state.get("total") or 0),
			"pending_outside_count": int(pending_state.get("outside") or 0),
			"pending_seen_in_target": bool(pending_seen_in_target),
			"refresh_clarification_button_count": int(refreshed.get("clarificationButtons") or 0),
			"refresh_user_count": int(refreshed.get("userCount") or 0),
			"initial_payload": initial_payload,
			"followup_payload": followup_payload,
			"analyze_response_count": len(analyze_responses),
			"trace_path": str(TRACE_PATH.relative_to(ROOT)),
			"pending_screenshot_path": str(SCREENSHOT_PENDING_PATH.relative_to(ROOT)),
			"final_screenshot_path": str(SCREENSHOT_FINAL_PATH.relative_to(ROOT)),
		}


def _run_api_empty_followup(base_url: str, browser_followup_payload: dict[str, Any]) -> dict[str, Any]:
	session_id = str(browser_followup_payload.get("session_id") or "")
	if not session_id:
		session_id = f"sess_clar_{uuid.uuid4().hex[:10]}"

	user_input = browser_followup_payload.get("user_input") if isinstance(browser_followup_payload.get("user_input"), dict) else {}
	user_context = browser_followup_payload.get("user_context") if isinstance(browser_followup_payload.get("user_context"), dict) else {}
	options = browser_followup_payload.get("options") if isinstance(browser_followup_payload.get("options"), dict) else {}

	recovery_answers = options.get("recovery_answers") if isinstance(options.get("recovery_answers"), dict) else {"clicked_link": False}
	base_text = str(user_input.get("text") or "I received a suspicious message and need safe steps.")

	followup_empty_payload = {
		"session_id": session_id,
		"user_input": {
			"text": base_text,
			"files": [],
		},
		"user_context": {
			"channel": str(user_context.get("channel") or "web-ui"),
			"locale": str(user_context.get("locale") or "en-IN"),
		},
		"options": {
			"stream": True,
			"generate_report": False,
			"clarification_followup": True,
			"trigger_mcp_actions": False,
			"response_instruction": str(options.get("response_instruction") or ""),
			"enforce_response_structure": True,
			"output_format": "summary_and_bullets",
			"recovery_answers": recovery_answers,
		},
	}

	ack = _http_json("POST", f"{base_url}/api/analyze", followup_empty_payload, timeout=30)
	run_id = str(ack.get("run_id") or "")
	if not run_id:
		raise RuntimeError("Empty-files follow-up analyze response missing run_id")
	result = _poll_result(base_url, run_id, timeout_s=180)

	needs_clarification = bool(result.get("needs_clarification"))
	insufficient_language = _contains_insufficient_language(result)
	stages = result.get("pipeline_stages") if isinstance(result.get("pipeline_stages"), list) else []
	fallback_stage_used = any("fallback" in str(s).lower() for s in stages)
	evidence_present = bool(result.get("why_this_decision"))

	return {
		"request": followup_empty_payload,
		"ack": ack,
		"result": result,
		"checks": {
			"resolved_without_extra_clarification": not needs_clarification,
			"no_insufficient_info_fallback_text": not insufficient_language,
			"legacy_fallback_stage_not_used": not fallback_stage_used,
			"evidence_narrative_present": evidence_present,
		},
	}


def main() -> int:
	parser = argparse.ArgumentParser(description="Run live clarification follow-up regression check")
	parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
	parser.add_argument("--timeout-browser", type=int, default=90)
	args = parser.parse_args()

	OUT_DIR.mkdir(parents=True, exist_ok=True)

	health = _ensure_health(args.base_url)
	browser = _run_browser_flow(args.base_url, timeout_s=max(30, int(args.timeout_browser)))

	followup_post = browser["followup_payload"]
	followup_post_sanitized = _sanitize_payload(followup_post)

	followup_pre_reconstructed = copy.deepcopy(followup_post)
	ui = followup_pre_reconstructed.get("user_input") if isinstance(followup_pre_reconstructed.get("user_input"), dict) else {}
	ui["files"] = []
	opts = followup_pre_reconstructed.get("options") if isinstance(followup_pre_reconstructed.get("options"), dict) else {}
	opts.pop("preprocessed_context", None)
	opts.pop("recovery_answers", None)
	opts.pop("clarification_followup", None)

	followup_pre_sanitized = _sanitize_payload(followup_pre_reconstructed)
	diff = _json_diff(followup_pre_sanitized, followup_post_sanitized)

	_write_json(POST_PAYLOAD_PATH, followup_post_sanitized)
	_write_json(PRE_PAYLOAD_PATH, followup_pre_sanitized)
	_write_json(DIFF_PAYLOAD_PATH, {"diff": diff})

	api_empty = _run_api_empty_followup(args.base_url, followup_post)
	api_empty_request_sanitized = _sanitize_payload(api_empty["request"])

	checks = {
		"ui_clarification_found": bool(browser.get("clarification_message_id")),
		"ui_no_synthetic_user_bubble": (
			int(browser["user_count_before_click"]) == int(browser["user_count_after_click"]) == int(browser["user_count_after_final"])
		),
		"ui_pending_in_same_card_only": bool(browser["pending_seen_in_target"]) and int(browser["pending_outside_count"]) == 0,
		"ui_refresh_no_stale_clarification": int(browser["refresh_clarification_button_count"]) == 0,
		"api_followup_empty_files_sent": len(api_empty["request"]["user_input"].get("files", [])) == 0,
		"api_followup_empty_files_resolved": bool(api_empty["checks"]["resolved_without_extra_clarification"]),
		"api_no_insufficient_info_fallback": bool(api_empty["checks"]["no_insufficient_info_fallback_text"]),
		"api_legacy_fallback_stage_not_used": bool(api_empty["checks"]["legacy_fallback_stage_not_used"]),
		"payload_diff_captures_followup_contract": any(
			item.get("path") in {
				"$.user_input.files",
				"$.options.recovery_answers",
				"$.options.clarification_followup",
				"$.options.preprocessed_context",
			}
			for item in diff
		),
	}

	report = {
		"generated_at": _utc_now(),
		"base_url": args.base_url,
		"health": health,
		"browser": {
			"prompt": browser["prompt"],
			"clarification_message_id": browser["clarification_message_id"],
			"user_count_before_click": browser["user_count_before_click"],
			"user_count_after_click": browser["user_count_after_click"],
			"user_count_after_final": browser["user_count_after_final"],
			"pending_in_same_card": browser["pending_in_same_card"],
			"pending_total_count": browser["pending_total_count"],
			"pending_outside_count": browser["pending_outside_count"],
			"pending_seen_in_target": browser["pending_seen_in_target"],
			"refresh_clarification_button_count": browser["refresh_clarification_button_count"],
			"refresh_user_count": browser["refresh_user_count"],
			"trace_path": browser["trace_path"],
			"pending_screenshot_path": browser["pending_screenshot_path"],
			"final_screenshot_path": browser["final_screenshot_path"],
		},
		"api_empty_followup": {
			"request": api_empty_request_sanitized,
			"ack": api_empty["ack"],
			"checks": api_empty["checks"],
			"result_excerpt": {
				"needs_clarification": bool(api_empty["result"].get("needs_clarification")),
				"requires_reporting": bool(api_empty["result"].get("requires_reporting")),
				"requires_emergency": bool(api_empty["result"].get("requires_emergency")),
				"chat_reply": str(api_empty["result"].get("chat_reply") or "")[:400],
				"summary": str(api_empty["result"].get("summary") or "")[:400],
				"pipeline_stages": api_empty["result"].get("pipeline_stages") or [],
			},
		},
		"payload_artifacts": {
			"postpatch": str(POST_PAYLOAD_PATH.relative_to(ROOT)),
			"prepatch_reconstructed": str(PRE_PAYLOAD_PATH.relative_to(ROOT)),
			"diff": str(DIFF_PAYLOAD_PATH.relative_to(ROOT)),
			"diff_entries": len(diff),
		},
		"checks": checks,
	}
	_write_json(REPORT_PATH, report)

	failed = [k for k, v in checks.items() if not bool(v)]
	if failed:
		print("CLARIFICATION LIVE CHECK: FAILED")
		for item in failed:
			print(f"- {item}")
		print(f"- report: {REPORT_PATH.relative_to(ROOT)}")
		return 1

	print("CLARIFICATION LIVE CHECK: PASSED")
	print(f"- report: {REPORT_PATH.relative_to(ROOT)}")
	print(f"- trace: {TRACE_PATH.relative_to(ROOT)}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
