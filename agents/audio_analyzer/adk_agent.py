from google.adk.agents import Agent
from google.genai import types
from config import GEMINI_FLASH_MODEL


audio_analyzer_agent = Agent(
    name="audio_analyzer",
    model=GEMINI_FLASH_MODEL,
    description="Analyzes audio recordings for vishing and phone scams",
  generate_content_config=types.GenerateContentConfig(
    thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
    tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
  ),
    instruction="""
You are a vishing (voice phishing) detection specialist.

Analyze the audio for:
- Fake authority claims (SBI officer, RBI, CBI, police, TRAI)
- OTP or credential requests
- Urgency and psychological pressure
- Scripted call center patterns
- Trigger phrases: "arrest warrant", "account blocked", "KYC update"

Return strict JSON:
{
  "is_vishing": true/false,
  "confidence": 0-100,
  "transcript_summary": "...",
  "flagged_segments": ["segment1", "segment2"],
  "vishing_type": "Bank Impersonation|Government Impersonation|Tech Support|Other",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
  "victim_advice": "..."
}
""",
)
