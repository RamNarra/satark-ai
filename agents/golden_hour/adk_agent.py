import os

from google.adk.agents import Agent

from config import GEMINI_FLASH_MODEL

try:
    from google.adk.tools import MCPToolset
    from google.adk.tools.mcp_tool.mcp_toolset import StdioConnectionParams
except Exception:
    MCPToolset = None  # type: ignore
    StdioConnectionParams = None  # type: ignore


def _build_google_mcp_toolset():
    """Build MCP toolset for Google services (Calendar + Gmail + Drive) via
    the official @modelcontextprotocol/server-google package.

    NOTE: @modelcontextprotocol/server-google-calendar does NOT exist on npm.
    The correct package is @modelcontextprotocol/server-google which covers
    Calendar, Gmail, and Drive in a single MCP server.

    Required env vars (set in .env):
        GOOGLE_CLIENT_ID
        GOOGLE_CLIENT_SECRET
        GOOGLE_REFRESH_TOKEN
    Optional:
        GOOGLE_APPLICATION_CREDENTIALS  (service-account path, if using SA)
        OPENAPI_MCP_HEADERS             (extra headers forwarded to MCP)
    """
    if MCPToolset is None or StdioConnectionParams is None:
        return None

    env = {}
    for key in [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GOOGLE_REFRESH_TOKEN",
        "OPENAPI_MCP_HEADERS",
    ]:
        value = os.getenv(key)
        if value:
            env[key] = value

    return MCPToolset(
        connection_params=StdioConnectionParams(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-google"],
            env=env or None,
        ),
        tool_name_prefix="google_mcp_",
    )


GOOGLE_MCP_TOOLSET = _build_google_mcp_toolset()
GOLDEN_HOUR_TOOLS = [GOOGLE_MCP_TOOLSET] if GOOGLE_MCP_TOOLSET is not None else []


golden_hour_agent = Agent(
    name="golden_hour_agent",
    model=GEMINI_FLASH_MODEL,
    description="Generates victim action plan, FIR-ready complaint, Google Calendar event, and Gmail draft",
    instruction="""
You are a cyber crime response specialist working for TGCSB (Telangana Cyber
Security Bureau). Your job is to generate an urgent, actionable response plan
for fraud victims using the Google MCP tools available to you.

Always include:
- 1930 helpline (National Cyber Crime Helpline)
- cybercrime.gov.in (NCRP portal)
- Golden Hour: if fraud happened < 1 hour ago, mark golden_hour_active = true

MCP Calendar integration (MANDATORY when golden_hour_active is true):
- Call google_mcp_calendar_create_event (or equivalent calendar tool from MCP)
- Use title exactly: FILE CYBERCRIME COMPLAINT — SATARK [case_id]
- Set start time to 30 minutes from now
- Set duration to 30 minutes
- Include https://cybercrime.gov.in and the 1930 helpline in the event description
- Add a popup reminder at 10 minutes before
- If golden_hour_active is false, skip calendar creation

MCP Gmail integration (MANDATORY when golden_hour_active is true):
- Call google_mcp_gmail_create_draft (or equivalent gmail tool from MCP)
- Subject: [SATARK ALERT] Cyber Fraud Complaint — [case_id]
- Body: Include full investigation summary, NCRP portal link, 1930 helpline, and pre-filled complaint text
- If MCP tools are unavailable, set gmail_draft.error accordingly

Generate a complete FIR-ready complaint template that matches the NCRP format.

Return strict JSON:
{
  "golden_hour_active": true/false,
  "priority_actions": [
    {"step": 1, "action": "...", "time_limit": "...", "contact": "..."}
  ],
  "victim_advice": "Detailed paragraph explaining what happened, why it is a scam, the psychological tricks used, and what the victim must do RIGHT NOW — minimum 4 sentences",
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
  },
  "gmail_draft": {
    "attempted": true/false,
    "created": true/false,
    "draft_id": "string or empty",
    "subject": "string or empty",
    "error": "empty if success"
  }
}
""",
    tools=GOLDEN_HOUR_TOOLS,
)
