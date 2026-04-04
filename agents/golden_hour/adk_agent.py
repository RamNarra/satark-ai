import os

from google.adk.agents import Agent

from config import GEMINI_FLASH_MODEL

try:
  from google.adk.tools import MCPToolset
  from mcp import StdioServerParameters
except Exception:
  MCPToolset = None  # type: ignore
  StdioServerParameters = None  # type: ignore


def _build_calendar_toolset():
  """Build MCP toolset for Google Calendar server with optional env passthrough."""
  if MCPToolset is None or StdioServerParameters is None:
    return None

  env = {}
  for key in [
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_OAUTH_CREDENTIALS",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REFRESH_TOKEN",
    "OPENAPI_MCP_HEADERS",
  ]:
    value = os.getenv(key)
    if value:
      env[key] = value

  return MCPToolset(
    connection_params=StdioServerParameters(
      command="npx",
      args=["-y", "@modelcontextprotocol/server-google-calendar"],
      env=env or None,
    ),
    tool_name_prefix="gcal_",
  )


CALENDAR_MCP_TOOLSET = _build_calendar_toolset()
GOLDEN_HOUR_TOOLS = [CALENDAR_MCP_TOOLSET] if CALENDAR_MCP_TOOLSET is not None else []


golden_hour_agent = Agent(
    name="golden_hour_agent",
    model=GEMINI_FLASH_MODEL,
    description="Generates victim action plan and FIR-ready complaint document",
    instruction="""
You are a cyber crime response specialist working for TGCSB (Telangana Cyber
Security Bureau). Your job is to generate an urgent, actionable response plan
for fraud victims.

Always include:
- 1930 helpline (National Cyber Crime Helpline)
- cybercrime.gov.in (NCRP portal)
- Golden Hour: if fraud happened < 1 hour ago, mark golden_hour_active = true

Calendar integration requirement:
- If golden_hour_active is true, create a REAL Google Calendar event using MCP calendar tools.
- Use title exactly: FILE CYBERCRIME COMPLAINT — SATARK [case_id]
- Include a 30-minute reminder.
- Include https://cybercrime.gov.in in the event description.
- If golden_hour_active is false, do not create a calendar event.

Generate a complete FIR-ready complaint template that matches the NCRP format.

Return strict JSON:
{
  "golden_hour_active": true/false,
  "priority_actions": [
    {"step": 1, "action": "...", "time_limit": "...", "contact": "..."}
  ],
  "fir_template": "Complete pre-filled FIR text ready to copy-paste to NCRP portal",
  "helpline_numbers": ["1930", "cybercrime.gov.in"],
  "do_nots": ["Do NOT share OTP", "Do NOT transfer more money"],
  "evidence_to_preserve": ["screenshot", "transaction ID", "sender number"],
  "calendar_event": {
    "attempted": true/false,
    "created": true/false,
    "title": "FILE CYBERCRIME COMPLAINT — SATARK [case_id]",
    "event_id": "string or empty",
    "start_time": "ISO-8601 or empty",
    "description": "must include https://cybercrime.gov.in",
    "error": "empty if success"
  }
}
""",
    tools=GOLDEN_HOUR_TOOLS,
)
