import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import GEMINI_API_KEY, MODEL_PRO_TOOLS, PROJECT_ID, LOCATION, MODEL_FLASH

client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)

SYSTEM_PROMPT = """You are a cybercrime response specialist at TGCSB.
The GOLDEN HOUR is the critical first hour after fraud — money can still be recovered.
Return ONLY valid JSON:
{
  "golden_hour_active": true,
  "minutes_to_act": 60,
  "priority_actions": [
    {
      "step": 1,
      "action": "Exact action to take",
      "whom_to_contact": "Agency name",
      "contact_details": "Phone or URL",
      "time_limit_minutes": 30,
      "why_critical": "Why this cannot wait"
    }
  ],
  "fir_template": {
    "section_ipc": ["66C IT Act", "420 IPC"],
    "complaint_portal": "cybercrime.gov.in",
    "case_summary": "FIR-ready paragraph",
    "evidence_to_preserve": ["WhatsApp screenshots", "transaction ID"]
  },
  "bank_freeze_needed": true,
  "immediate_helpline": "1930",
  "recovery_probability": "HIGH|MEDIUM|LOW"
}"""

def run(input_data: dict) -> dict:
    summary = f"""
Scam Type: {input_data.get("scam_type", "unknown")}
Confidence: {input_data.get("confidence", 0)}%
Risk Level: {input_data.get("risk_level", "unknown")}
Fraud Amount: Rs.{input_data.get("fraud_amount", "unknown")}
Suspect Phone: {input_data.get("suspect_phone", "none")}
Suspect Domain: {input_data.get("suspect_domain", "none")}
OSINT Threat Score: {input_data.get("osint_threat_score", 0)}/100
OSINT Summary: {input_data.get("osint_summary", "not available")}
Minutes Since Fraud: {input_data.get("minutes_since_fraud", "unknown")}
Victim Complaint: {input_data.get("original_complaint", "")[:300]}
"""
    try:
        resp = client.models.generate_content(
            model=MODEL_FLASH,
            contents=f"Generate a Golden Hour response plan:\n{summary}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        return json.loads(resp.text.strip())
    except Exception as e:
        return {
            "golden_hour_active": True,
            "minutes_to_act": 60,
            "priority_actions": [
                {"step": 1, "action": "Call National Cybercrime Helpline",
                 "whom_to_contact": "NCRP", "contact_details": "1930",
                 "time_limit_minutes": 5, "why_critical": "Bank freeze request"},
                {"step": 2, "action": "File complaint online",
                 "whom_to_contact": "NCRP Portal",
                 "contact_details": "cybercrime.gov.in",
                 "time_limit_minutes": 30, "why_critical": "Creates official case number"}
            ],
            "immediate_helpline": "1930",
            "recovery_probability": "MEDIUM",
            "error": str(e)
        }