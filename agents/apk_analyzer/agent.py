import os, sys, json, hashlib, zipfile, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import GEMINI_API_KEY, MODEL_FLASH

client = genai.Client(api_key=GEMINI_API_KEY)

DANGEROUS_PERMISSIONS = [
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "RECORD_AUDIO", "CAMERA", "READ_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION",
    "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
    "RECEIVE_BOOT_COMPLETED",
]

def extract_apk_info(apk_bytes: bytes) -> dict:
    import tempfile
    result = {
        "permissions": [], "dangerous_permissions": [],
        "hardcoded_ips": [], "hardcoded_urls": [],
        "c2_servers": [], "apk_hash": "", "package_name": "",
        "strings_suspicious": [], "error": None
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
        ip_pat  = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        url_pat = r"https?://[^\s'\"<>]{6,100}"
        result["hardcoded_ips"]  = list(set(re.findall(ip_pat, text)))[:20]
        result["hardcoded_urls"] = list(set(re.findall(url_pat, text)))[:20]
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

def run(input_data: dict) -> dict:
    apk_bytes = input_data.get("bytes", b"")
    if not apk_bytes:
        return {"error": "No APK bytes provided", "is_malicious": False}

    static = extract_apk_info(apk_bytes)

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
C2 Candidates: {static["c2_servers"]}
Suspicious Keywords: {static["strings_suspicious"]}
DEX Files: {static.get("dex_files", [])}"""

    try:
        resp = client.models.generate_content(
            model=MODEL_FLASH,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        verdict = json.loads(resp.text.strip())
        verdict["static_analysis"] = static
        return verdict
    except Exception as e:
        static["error"] = str(e)
        static["is_malicious"] = len(static.get("c2_servers", [])) > 0
        return static