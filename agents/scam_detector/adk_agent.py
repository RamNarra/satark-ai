from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from config import GEMINI_PRO_MODEL
from db.operations import find_similar_patterns, check_threat_intel


def check_known_patterns(scam_type: str = "", message_text: str = "") -> dict:
    """Check Firestore for previously seen similar patterns."""
    similar = find_similar_patterns(
        query_text=message_text or "",
        scam_type=scam_type or None,
        limit=10,
        min_score=20,
    )
    return {
        "similar_cases_found": len(similar),
        "message": f"Found {len(similar)} similar cases in database" if similar else "No prior cases found",
        "top_matches": [
            {
                "scam_type": row.get("scam_type", "UNKNOWN"),
                "sub_type": row.get("sub_type", ""),
                "score": row.get("score", 0),
            }
            for row in similar[:3]
        ],
    }


def check_known_ioc(indicator: str) -> dict:
    """Check if a URL, phone, or domain is a known threat indicator."""
    result = check_threat_intel(indicator)
    if result:
        return {"known_threat": True, "details": result}
    return {"known_threat": False, "details": None}


scam_detector_agent = Agent(
    name="scam_detector",
    model=GEMINI_PRO_MODEL,
    description="Detects and classifies cyber scams in text and images",
    instruction="""
You are a cyber scam detection specialist for India. Analyze the provided
text or image and detect signs of fraud.

Look for: urgency language, authority impersonation (SBI/RBI/police),
OTP/credential requests, suspicious URLs, UPI fraud, job scams,
investment fraud, lottery scams, KYC fraud.

Use check_known_patterns to query the database for similar prior cases (include message_text when available).
Use check_known_ioc to check any URLs or phone numbers found.

Return strict JSON:
{
  "is_scam": true/false,
  "scam_type": "UPI Impersonation|Phishing|Investment Fraud|Job Scam|KYC Fraud|Ransomware|Other",
  "confidence": 0-100,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
  "red_flags": ["flag1", "flag2"],
  "extracted_entities": {
    "urls": [], "phones": [], "upi_ids": [], "account_numbers": []
  },
  "victim_advice": "plain language advice",
  "similar_cases_found": 0
}
""",
    tools=[
        FunctionTool(func=check_known_patterns),
        FunctionTool(func=check_known_ioc),
    ],
)
