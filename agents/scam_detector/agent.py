import json, re, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import GEMINI_API_KEY, MODEL_PRO, MODEL_PRO_TOOLS, PROJECT_ID, LOCATION

client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)

SYSTEM_PROMPT = """You are an expert cybercrime analyst trained by TGCSB (Telangana Cyber Security Bureau).
Analyze messages for fraud. Respond ONLY with valid JSON:
{
  "is_scam": true,
  "confidence": 0,
  "scam_type": "UPI Fraud|Impersonation|Investment Fraud|OTP Theft|KYC Fraud|Job Scam|Lottery Scam|Romance Scam|Tech Support|Loan Fraud|null",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "signals_found": ["red flag 1", "red flag 2"],
  "extracted_entities": {
    "phone_numbers": [], "urls": [], "amounts": [],
    "bank_names": [], "government_agencies": []
  },
  "language_detected": "en|hi|te|other",
  "victim_advice": "One clear action for the victim",
  "summary": "Two-sentence law enforcement summary"
}"""

def analyze_text(text: str) -> dict:
    try:
        resp = client.models.generate_content(
            model=MODEL_PRO,
            contents=f"Analyze this for fraud:\n\n{text}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        return json.loads(resp.text.strip())
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", resp.text, re.DOTALL)
        return json.loads(m.group()) if m else {"is_scam": False, "confidence": 0, "error": "parse_failed"}
    except Exception as e:
        return {"is_scam": False, "confidence": 0, "error": str(e)}

def analyze_image(image_bytes: bytes, mime_type: str = "image/jpeg") -> dict:
    try:
        resp = client.models.generate_content(
            model=MODEL_PRO,
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
                "Analyze this image for cybercrime indicators. Extract all text, URLs, phone numbers."
            ],
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        return json.loads(resp.text.strip())
    except Exception as e:
        return {"is_scam": False, "confidence": 0, "error": str(e)}

def run(input_data: dict) -> dict:
    if input_data.get("type") == "image":
        return analyze_image(input_data["bytes"], input_data.get("mime_type", "image/jpeg"))
    return analyze_text(input_data.get("text", ""))