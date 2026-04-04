import os, sys, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import GEMINI_API_KEY, MODEL_PRO, MODEL_FLASH, PROJECT_ID, LOCATION

client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)

SYSTEM_PROMPT = """You are a vishing (voice phishing) detection expert at TGCSB.
Analyze call transcripts for social engineering. Respond ONLY with valid JSON:
{
  "is_vishing": true,
  "confidence": 0,
  "vishing_type": "bank_impersonation|police_impersonation|IT_support|loan_officer|government_official|null",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "urgency_tactics_used": ["tactic1"],
  "impersonated_entity": "name of bank/org or null",
  "extracted_entities": {
    "phone_numbers": [], "account_numbers": [], "amounts": []
  },
  "language_detected": "en|hi|te|other",
  "call_summary": "2-3 sentence summary for FIR filing",
  "victim_advice": "Immediate action the victim should take"
}"""

def analyze_audio_file(audio_bytes: bytes, mime_type: str = "audio/mp3") -> dict:
    try:
        resp = client.models.generate_content(
            model=MODEL_FLASH,
            contents=[
                types.Part.from_bytes(data=audio_bytes, mime_type=mime_type),
                "Transcribe and analyze this call recording for vishing/fraud."
            ],
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        return json.loads(resp.text.strip())
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", resp.text, re.DOTALL)
        return json.loads(m.group()) if m else {"is_vishing": False, "confidence": 0, "error": "parse_failed"}
    except Exception as e:
        return {"is_vishing": False, "confidence": 0, "error": str(e)}

def analyze_transcript(transcript: str) -> dict:
    try:
        resp = client.models.generate_content(
            model=MODEL_PRO,
            contents=f"Analyze this call transcript for vishing:\n\n{transcript}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                response_mime_type="application/json"
            )
        )
        return json.loads(resp.text.strip())
    except Exception as e:
        return {"is_vishing": False, "confidence": 0, "error": str(e)}

def run(input_data: dict) -> dict:
    if input_data.get("type") == "audio":
        return analyze_audio_file(
            input_data["bytes"],
            input_data.get("mime_type", "audio/mp3")
        )
    elif input_data.get("type") == "transcript":
        return analyze_transcript(input_data.get("text", ""))
    return {"is_vishing": False, "confidence": 0, "error": "unsupported input type"}