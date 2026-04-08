import os, sys, json, uuid
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from agents.scam_detector import agent as scam_detector
from agents.osint import agent as osint_agent
from agents.apk_analyzer import agent as apk_analyzer
from agents.audio_analyzer import agent as audio_analyzer
from agents.golden_hour import agent as golden_hour

def run(input_data: dict) -> dict:
    case_id = str(uuid.uuid4())[:8].upper()
    ack_id  = f"SATARK-{datetime.now().strftime('%Y%m%d')}-{case_id}"
    result  = {
        "acknowledgment_id": ack_id,
        "timestamp": datetime.now().isoformat(),
        "pipeline_stages": {}
    }

    # Stage 1: Detection
    print(f"[{ack_id}] Stage 1: Detection...")
    input_type = input_data.get("type", "text")
    if input_type == "audio":
        detection = audio_analyzer.run(input_data)
        detection["is_scam"] = detection.get("is_vishing", False)
        detection.setdefault("extracted_entities", {})
    elif input_type == "apk":
        detection = apk_analyzer.run(input_data)
        detection["is_scam"] = detection.get("is_malicious", False)
        detection.setdefault("extracted_entities", {})
    else:
        detection = scam_detector.run(input_data)

    result["pipeline_stages"]["detection"] = detection
    result["scam_type"]     = detection.get("scam_type")
    result["confidence"]    = detection.get("confidence", 0)
    result["risk_level"]    = detection.get("risk_level", "LOW")
    result["is_scam"]       = detection.get("is_scam", False)
    result["language"]      = detection.get("language_detected", "en")
    result["victim_advice"] = detection.get("victim_advice", "")
    result["signals_found"] = detection.get("signals_found", [])

    # Stage 2: OSINT (run when indicators exist)
    osint_result = {"threat_summary": "Skipped (no indicators)", "overall_threat_score": 0}
    extracted_entities = detection.get("extracted_entities", {}) if isinstance(detection.get("extracted_entities"), dict) else {}
    urls = extracted_entities.get("urls") or []
    phones = extracted_entities.get("phone_numbers") or extracted_entities.get("phones") or []
    domains = extracted_entities.get("domains") or []
    has_indicators = bool(urls) or bool(phones) or bool(domains)
    if has_indicators:
        print(f"[{ack_id}] Stage 2: OSINT...")
        try:
            osint_result = osint_agent.run(detection)
        except Exception as e:
            osint_result = {"error": str(e), "overall_threat_score": 0}
    result["pipeline_stages"]["osint"] = osint_result

    # Stage 3: Golden Hour
    print(f"[{ack_id}] Stage 3: Golden Hour...")
    entities = detection.get("extracted_entities", {})
    golden_result = golden_hour.run({
        "scam_type":           result["scam_type"],
        "confidence":          result["confidence"],
        "risk_level":          result["risk_level"],
        "fraud_amount":        input_data.get("fraud_amount", 0),
        "suspect_phone":       (entities.get("phone_numbers") or [""])[0],
        "suspect_domain":      (entities.get("urls") or [""])[0],
        "osint_threat_score":  osint_result.get("overall_threat_score", 0),
        "osint_summary":       osint_result.get("threat_summary", ""),
        "apk_malicious":       detection.get("is_malicious", False),
        "minutes_since_fraud": input_data.get("minutes_since_fraud"),
        "original_complaint":  input_data.get("text", ""),
    })
    result["pipeline_stages"]["golden_hour"] = golden_result

    result["immediate_helpline"]   = "1930"
    result["complaint_portal"]     = "cybercrime.gov.in"
    result["recovery_probability"] = golden_result.get("recovery_probability", "MEDIUM")
    result["priority_actions"]     = golden_result.get("priority_actions", [])
    result["fir_template"]         = golden_result.get("fir_template", {})

    print(f"[{ack_id}] Done. Risk: {result['risk_level']} | Confidence: {result['confidence']}%")
    return result