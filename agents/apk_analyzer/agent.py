import os
import sys
import json
import hashlib
import zipfile
import re
from urllib.parse import urlparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import GEMINI_API_KEY, MODEL_FLASH

client = genai.Client(api_key=GEMINI_API_KEY)


def _response_text(resp) -> str:
    try:
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            parts = candidates[0].content.parts
            return "".join(
                t
                for t in (getattr(p, "text", None) for p in (parts or []))
                if isinstance(t, str) and t
            )
    except Exception:
        pass
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        t = resp.get("text")
        return t if isinstance(t, str) else ""
    return ""


def _append_candidate_content(history: list, resp) -> None:
    """Append the model's full Content (including thought signature parts)."""

    try:
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            history.append(candidates[0].content)
    except Exception:
        pass

DANGEROUS_PERMISSIONS = [
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "RECORD_AUDIO", "CAMERA", "READ_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION",
    "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
    "RECEIVE_BOOT_COMPLETED",
]

SUSPICIOUS_PERMISSIONS = [
    "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE",
    "SYSTEM_ALERT_WINDOW",
    "WRITE_SETTINGS",
    "RECEIVE_BOOT_COMPLETED",
]

KNOWN_TRAINING_MARKERS = [
    "insecurebankv2",
    "owasp",
    "training app",
    "vulnerable app",
    "security lab",
]

def extract_apk_info(apk_bytes: bytes) -> dict:
    import tempfile
    result = {
        "permissions": [],
        "dangerous_permissions": [],
        "hardcoded_ips": [],
        "hardcoded_urls": [],
        "c2_servers": [],
        "apk_hash": "",
        "package_name": "",
        "app_name": "",
        "version_name": "",
        "version_code": 0,
        "min_sdk": None,
        "target_sdk": None,
        "strings_suspicious": [],
        "all_strings": [],
        "repo_links": [],
        "emails": [],
        "error": None,
    }
    try:
        result["apk_hash"] = hashlib.sha256(apk_bytes).hexdigest()
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            tmp_path = f.name
        try:
            with zipfile.ZipFile(tmp_path, "r") as z:
                result["dex_files"] = [n for n in z.namelist() if n.endswith(".dex")]
                result["file_count"] = len(z.namelist())
        finally:
            os.unlink(tmp_path)

        text = apk_bytes.decode("latin-1", errors="ignore")
        ascii_strings = re.findall(r"[ -~]{4,120}", text)
        result["all_strings"] = list(dict.fromkeys(ascii_strings))[:4000]

        ip_pat  = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        url_pat = r"https?://[^\s'\"<>]{6,100}"
        pkg_pat = r"\b(?:[a-zA-Z_][a-zA-Z0-9_]*\.){2,}[a-zA-Z0-9_]+\b"
        perm_pat = r"android\.permission\.[A-Z_]+"
        email_pat = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        result["hardcoded_ips"]  = list(set(re.findall(ip_pat, text)))[:20]
        result["hardcoded_urls"] = list(set(re.findall(url_pat, text)))[:20]
        package_candidates = [x for x in re.findall(pkg_pat, text) if x.count(".") >= 2]
        if package_candidates:
            result["package_name"] = package_candidates[0]
        permissions = [p.split(".")[-1] for p in re.findall(perm_pat, text)]
        result["permissions"] = list(dict.fromkeys(permissions))[:120]
        result["dangerous_permissions"] = [p for p in result["permissions"] if p in DANGEROUS_PERMISSIONS]
        result["emails"] = list(dict.fromkeys(re.findall(email_pat, text)))[:20]
        result["repo_links"] = [u for u in result["hardcoded_urls"] if "github.com" in u.lower()][:10]

        if filename := result.get("filename"):
            stem = os.path.splitext(os.path.basename(str(filename)))[0]
            if stem:
                result["app_name"] = stem

        if not result["app_name"]:
            for s in result["all_strings"]:
                low = s.lower()
                if any(marker in low for marker in KNOWN_TRAINING_MARKERS):
                    result["app_name"] = s.strip()[:80]
                    break

        result["c2_servers"] = [
            u for u in result["hardcoded_urls"]
            if not any(legit in u for legit in [
                "google.com","android.com","gstatic.com",
                "googleapis.com","firebase.google.com"
            ])
        ]
        suspicious_keywords = ["otp","steal","exfil","harvest",
                               "keylog","intercept","credential"]
        result["strings_suspicious"] = [
            kw for kw in suspicious_keywords if kw in text.lower()
        ]
    except Exception as e:
        result["error"] = str(e)
    return result


def run_static_analysis(apk_bytes: bytes, filename: str | None = None) -> dict:
    """Compatibility helper for the ADK pipeline.

    Returns a lightweight static report suitable to pass into an LLM prompt.
    """
    report = extract_apk_info(apk_bytes)
    if filename:
        report["filename"] = filename
    return report


def _risk_level_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "SAFE"


def build_apk_analysis_contract(static: dict, filename: str | None = None) -> dict:
    file_name = str(filename or static.get("filename") or "uploaded.apk")
    app_name = str(static.get("app_name") or os.path.splitext(os.path.basename(file_name))[0] or "UnknownApp")
    package_name = str(static.get("package_name") or "")
    dangerous = [str(p) for p in static.get("dangerous_permissions") or []]
    permissions = [str(p) for p in static.get("permissions") or []]
    suspicious_perms = [p for p in permissions if p in SUSPICIOUS_PERMISSIONS]

    urls = [str(u) for u in static.get("hardcoded_urls") or []]
    domains = []
    for url in urls:
        try:
            host = (urlparse(url).netloc or "").strip().lower()
            if host:
                domains.append(host)
        except Exception:
            continue
    domains = list(dict.fromkeys(domains))[:30]

    labels = [app_name]
    blob = " ".join([
        app_name,
        package_name,
        " ".join(str(x) for x in (static.get("all_strings") or [])[:200]),
    ]).lower()
    for marker in KNOWN_TRAINING_MARKERS:
        if marker in blob:
            labels.append(marker)

    known_training = any(marker in blob for marker in KNOWN_TRAINING_MARKERS)
    score = 0
    score += min(len(dangerous) * 12, 40)
    score += min(len(suspicious_perms) * 10, 30)
    score += min(len(static.get("c2_servers") or []) * 8, 24)
    score += min(len(static.get("strings_suspicious") or []) * 8, 24)
    if known_training:
        score = max(0, score - 25)

    risk_level = _risk_level_from_score(score)
    is_malicious = score >= 70 and not known_training
    malware_type = "Clean"
    if is_malicious and any(k in (static.get("strings_suspicious") or []) for k in ["otp", "credential"]):
        malware_type = "Credential Harvester"
    elif is_malicious:
        malware_type = "Banking Trojan"
    elif known_training:
        malware_type = "Known Training App"

    behavioral_flags = []
    for perm in dangerous:
        behavioral_flags.append(
            {
                "flag": f"uses_{perm.lower()}",
                "severity": "high" if perm in {"READ_SMS", "SEND_SMS", "RECORD_AUDIO"} else "medium",
                "evidence": f"Manifest/string references android.permission.{perm}",
            }
        )
    if static.get("c2_servers"):
        behavioral_flags.append(
            {
                "flag": "suspicious_network_endpoints",
                "severity": "high",
                "evidence": f"Found {len(static.get('c2_servers') or [])} non-trusted hardcoded URL(s)",
            }
        )

    identity_assessment = {
        "likely_known_project": bool(known_training),
        "likely_official_project": bool(known_training and "github" in " ".join(static.get("repo_links") or []).lower()),
        "likely_repack_or_tampered": "unknown" if not known_training else "possible",
    }

    summary = "Static APK analysis completed with identity and risk indicators."
    if known_training:
        summary = "APK naming and strings align with a known intentionally vulnerable training app profile."
    elif is_malicious:
        summary = "APK shows elevated risk markers consistent with potentially malicious behavior."

    confidence_0_1 = round(min(0.98, 0.45 + (score / 140.0)), 2)

    return {
        "artifact_type": "apk_analysis",
        "file_name": file_name,
        "sha256": str(static.get("apk_hash") or ""),
        "package_name": package_name,
        "app_name": app_name,
        "version_name": str(static.get("version_name") or ""),
        "version_code": int(static.get("version_code") or 0),
        "min_sdk": static.get("min_sdk"),
        "target_sdk": static.get("target_sdk"),
        "signing": {
            "is_debug": "android debug" in blob,
            "cert_subject": "",
            "cert_issuer": "",
            "cert_sha256": "",
        },
        "permissions": {
            "all": permissions,
            "dangerous": dangerous,
            "suspicious": suspicious_perms,
        },
        "components": {
            "exported_activities": [],
            "exported_services": [],
            "exported_receivers": [],
            "deep_links": [],
        },
        "network_indicators": {
            "urls": urls,
            "domains": domains,
            "ip_literals": [str(x) for x in static.get("hardcoded_ips") or []],
        },
        "code_indicators": {
            "hardcoded_secrets": [s for s in (static.get("all_strings") or []) if "api_key" in str(s).lower()][:10],
            "crypto_issues": [s for s in ["hardcoded_key" if "hardcoded" in blob else "", "weak_cipher" if "des/ecb" in blob else ""] if s],
            "webview_risks": ["javascript_enabled"] if "setjavascriptenabled(true)" in blob else [],
            "root_detection": "root" in blob and "detect" in blob,
            "anti_analysis": any(k in blob for k in ["frida", "debugger", "emulator"]),
        },
        "behavioral_flags": behavioral_flags[:12],
        "identity_clues": {
            "labels": list(dict.fromkeys(labels))[:10],
            "author_strings": [s for s in (static.get("all_strings") or []) if "author" in str(s).lower() or "developer" in str(s).lower()][:10],
            "repo_links": [str(x) for x in static.get("repo_links") or []],
            "emails": [str(x) for x in static.get("emails") or []],
        },
        "identity_assessment": identity_assessment,
        "analysis_summary": summary,
        "confidence": confidence_0_1,
        "is_malicious": is_malicious,
        "malware_type": malware_type,
        "risk_level": risk_level,
        "dangerous_permissions": dangerous,
        "c2_servers": [str(x) for x in static.get("c2_servers") or []],
        "suspicious_strings": [str(x) for x in static.get("strings_suspicious") or []],
        "plain_english_summary": summary,
        "victim_advice": (
            "Treat this APK as untrusted on your personal phone. Remove it and avoid entering real credentials."
            if not known_training
            else "This appears to be a training-style vulnerable app, but only use it in an isolated test environment."
        ),
    }

def run(input_data: dict) -> dict:
    apk_bytes = input_data.get("bytes", b"")
    if not apk_bytes:
        return {"error": "No APK bytes provided", "is_malicious": False}

        static = extract_apk_info(apk_bytes)
        static["filename"] = str(input_data.get("filename") or "uploaded.apk")

        prompt = f"""You are a mobile malware analyst at TGCSB.
Analyze this APK static report and return ONLY valid JSON:
{{
    "is_malicious": true,
    "malware_type": "credential_harvester|otp_stealer|spyware|trojan|legitimate|unknown",
    "confidence": 0,
    "threat_summary": "2-3 sentences for law enforcement",
    "dangerous_findings": ["finding1"],
    "c2_servers": [],
    "recommended_action": "DO NOT INSTALL / Safe to use / Needs further analysis"
}}

APK Hash: {static["apk_hash"]}
Package: {static.get("package_name")}
C2 Candidates: {static["c2_servers"]}
Suspicious Keywords: {static["strings_suspicious"]}
DEX Files: {static.get("dex_files", [])}"""

    try:
        history = [
            types.Content(
                role="user",
                parts=[types.Part(text=prompt)],
            )
        ]
        resp = client.models.generate_content(
            model=MODEL_FLASH,
            contents=history,
            config=types.GenerateContentConfig(
                temperature=0.1,
                thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
                tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
                response_mime_type="application/json"
            )
        )
        _append_candidate_content(history, resp)
        verdict = json.loads(_response_text(resp).strip())
        contract = build_apk_analysis_contract(static, filename=input_data.get("filename"))
        contract["static_analysis"] = static
        contract["llm_verdict"] = verdict

        # Keep compatibility with existing fields while prioritizing contract output.
        contract["is_malicious"] = bool(verdict.get("is_malicious", contract.get("is_malicious")))
        contract["malware_type"] = str(verdict.get("malware_type") or contract.get("malware_type") or "unknown")
        contract["threat_summary"] = str(verdict.get("threat_summary") or contract.get("analysis_summary") or "")
        contract["recommended_action"] = str(verdict.get("recommended_action") or contract.get("victim_advice") or "")
        return contract
    except Exception as e:
        static["error"] = str(e)
        contract = build_apk_analysis_contract(static, filename=input_data.get("filename"))
        contract["error"] = str(e)
        return contract