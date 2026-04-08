import json, re, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import GEMINI_API_KEY, MODEL_PRO, MODEL_PRO_TOOLS, PROJECT_ID, LOCATION

client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)


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
    """Append the model's full Content (including thought signature parts).

    gemini-3-* multi-step tool-calling requires the 'thought signature' parts to
    be echoed back on the next turn. Keeping the full Content object is the
    safest way to preserve this.
    """

    try:
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            history.append(candidates[0].content)
    except Exception:
        pass

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
        history = [
            types.Content(
                role="user",
                parts=[types.Part(text=f"Analyze this for fraud:\n\n{text}")],
            )
        ]
        resp = client.models.generate_content(
            model=MODEL_PRO,
            contents=history,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
                tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
                response_mime_type="application/json"
            )
        )
        _append_candidate_content(history, resp)
        return json.loads(_response_text(resp).strip())
    except json.JSONDecodeError:
        raw = _response_text(resp)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return json.loads(m.group()) if m else {"is_scam": False, "confidence": 0, "error": "parse_failed"}
    except Exception as e:
        return {"is_scam": False, "confidence": 0, "error": str(e)}

def analyze_image(image_bytes: bytes, mime_type: str = "image/jpeg") -> dict:
    try:
        history = [
            types.Content(
                role="user",
                parts=[
                    types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
                    types.Part(text="Analyze this image for cybercrime indicators. Extract all text, URLs, phone numbers."),
                ],
            )
        ]
        resp = client.models.generate_content(
            model=MODEL_PRO,
            contents=history,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
                tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
                response_mime_type="application/json"
            )
        )
        _append_candidate_content(history, resp)
        return json.loads(_response_text(resp).strip())
    except Exception as e:
        return {"is_scam": False, "confidence": 0, "error": str(e)}

def run(input_data: dict) -> dict:
    if input_data.get("type") == "image":
        return analyze_image(input_data["bytes"], input_data.get("mime_type", "image/jpeg"))
    return analyze_text(input_data.get("text", ""))