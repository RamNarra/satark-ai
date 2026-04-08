from google.adk.agents import Agent
from google.genai import types
from config import GEMINI_PRO_MODEL


apk_analyzer_agent = Agent(
    name="apk_analyzer",
    model=GEMINI_PRO_MODEL,
    description="Performs static malware analysis on APK files",
  generate_content_config=types.GenerateContentConfig(
    thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
    tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
  ),
    instruction="""
You are a mobile malware forensics specialist.

Given the static analysis results of an APK (permissions, strings,
manifest data, hashes), determine if it is malicious.

Focus on:
- Dangerous permissions: READ_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION
- Hardcoded C2 server IPs or URLs
- Fake bank/government app clones
- OTP-stealing capability

Return strict JSON:
{
  "is_malicious": true/false,
  "malware_type": "Banking Trojan|Spyware|Adware|Ransomware|Credential Harvester|Clean",
  "confidence": 0-100,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
  "dangerous_permissions": [],
  "c2_servers": [],
  "suspicious_strings": [],
  "plain_english_summary": "...",
  "victim_advice": "..."
}
""",
)
