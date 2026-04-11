"""
Chat Orchestrator — the primary entry point for all user interactions.

This module implements the exact conversational flow from the product vision:
1. User sends text / screenshot / audio / APK
2. Manager triages and decides if context is missing
3. Context agent asks 1–3 adaptive MCQs only when needed
4. Risk agent classifies: safe → clicked → shared → money_lost
5. Natural language reply with case-specific guidance
6. If money lost within golden hour → trigger Calendar, Tasks
7. After urgent phase → ask for full story → generate Doc + Gmail draft
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from google import genai
from google.genai import types
from config import MODEL_FLASH, PROJECT_ID, LOCATION

logger = logging.getLogger("uvicorn.error")

_client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _response_text(resp) -> str:
    try:
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            parts = candidates[0].content.parts
            return "".join(
                t for t in (getattr(p, "text", None) for p in (parts or []))
                if isinstance(t, str) and t
            )
    except Exception:
        pass
    return ""


def _parse_json(text: str) -> dict:
    """Best-effort parse JSON from model output, tolerating markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# System prompts — the ONLY place wording policy lives.
# Everything else is orchestration logic.
# ---------------------------------------------------------------------------

MANAGER_SYSTEM_PROMPT = """You are SATARK, a calm cyber-fraud assistance agent for ordinary people in India.

Your job is to understand suspicious digital incidents, ask only the minimum follow-up questions needed, assess the user's level of risk, and guide them with practical next steps.

Behavior rules:
1. Do NOT panic the user. Do NOT blame the user. Do NOT say "you should have known".
2. If the user appears safe, reassure them clearly and briefly.
3. If the user clicked but did not share details, explain the likely risk without exaggeration.
4. If the user shared credentials or personal data, recommend only context-relevant recovery steps.
5. If the user lost money, treat it as urgent and help trigger immediate action.
6. Ask at most 3 clarification questions at a time. Prefer yes/no or multiple-choice.
7. Use plain, natural English suitable for Indian users who are not native English speakers. Around IELTS band 7 level.
8. Do NOT sound robotic, legal-heavy, or overly formal. Do NOT use words like "kindly be informed" or "per our analysis" or "it is imperative".
9. Do NOT output generic boilerplate. Tailor your response to what actually happened.
10. Keep sentences short to medium length. Be concise but helpful.
11. Recognise common scam patterns: shortened links (bit.ly, cutt.ly, tinyurl), fake KYC, fake customer care, UPI fraud, job scams, investment scams, lottery scams, sextortion, loan fraud, etc.
12. When information is missing, ask questions. When enough info is available, give your assessment.
13. Never pretend certainty when evidence is incomplete. Say "this looks like" not "this is definitely".

When you need to ask clarification questions, return JSON:
{
  "action": "ask_questions",
  "questions": [
    {"id": "q1", "text": "Did you click the link?", "options": ["Yes", "No"]}
  ],
  "reasoning": "why these questions are needed"
}

When you have enough information to assess, return JSON:
{
  "action": "assess",
  "risk_stage": "safe_exposure|clicked_no_share|shared_details|financial_loss",
  "likely_scam_type": "Phishing|UPI Fraud|KYC Fraud|Job Scam|Investment Fraud|Loan Fraud|Customer Care Fraud|Sextortion|Identity Theft|Other|null",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 75,
  "chat_reply": "The natural language message to show the user",
  "action_steps": ["Step 1", "Step 2"],
  "needs_golden_hour": false,
  "needs_detailed_story": false,
  "signals_found": ["signal 1", "signal 2"]
}

Important: The chat_reply field must be your natural, conversational response. Write it like a calm, smart cyber-help officer talking to a stressed person. NOT a bullet list of facts. A real human response.
"""

MCQ_GENERATOR_PROMPT = """You generate clarification questions for a cyber-fraud assistant.

Your goal is to reduce uncertainty with the fewest possible questions.

Rules:
- Ask at most 3 questions
- Prefer yes/no or multiple-choice
- Only ask what is necessary for deciding next actions
- Avoid repeating information already given
- Adapt to modality: text, screenshot, audio, APK
- If risk is already low and user is likely safe, ask fewer questions
- If money loss or credential exposure is possible, ask the minimum questions needed

Example missing facts to probe:
- whether a link was clicked
- whether any information was entered
- what kind of information was shared
- whether money was lost
- when the money loss happened
- whether an APK was installed
- whether OTPs were received after

Return ONLY valid JSON:
{
  "needs_questions": true,
  "questions": [
    {"id": "clicked_link", "text": "Did you click the link?", "options": ["Yes", "No"]}
  ],
  "reasoning": "Need to determine exposure level before giving next-step advice."
}
"""

GOLDEN_HOUR_PLANNER_PROMPT = """You are a golden-hour cyber incident planner.

Use the case details to create an urgent action plan for a user who lost money to a cyber fraud.

Your plan must:
- Prioritize actions in time order
- Be realistic about what can be done
- Use simple English
- Include only relevant steps for THIS case
- Fit into the remaining golden-hour window
- Help create calendar events and task items

Consider actions like:
- Call 1930 (national cybercrime helpline)
- Inform bank / freeze account or card if relevant
- Secure compromised credentials (passwords, PINs)
- Preserve evidence (screenshots, transaction IDs, chat logs)
- File online complaint at cybercrime.gov.in

Choose based on the actual case. Not every case needs every action.

Return ONLY valid JSON:
{
  "is_golden_hour": true,
  "minutes_since_loss": 10,
  "minutes_remaining": 50,
  "headline": "Golden hour is active. Please act now.",
  "ordered_actions": [
    {
      "title": "Call 1930 now",
      "duration_minutes": 10,
      "description": "Report the fraud immediately. Keep transaction details ready."
    }
  ],
  "chat_summary": "A natural conversational summary for the user explaining urgency and steps",
  "calendar_title": "Golden Hour — Act Now",
  "calendar_description": "Steps to take in the next N minutes",
  "task_items": ["Call 1930", "Contact bank", "Change passwords"]
}
"""

COMPLAINT_DOC_PROMPT = """You are a cyber incident documentation agent.

Convert the user's story and case details into:
1. A formal complaint / FIR-style document
2. A shorter human-readable email summary

Rules:
- Reflect the user's actual story accurately
- Do not invent missing facts — mark unknowns clearly
- Maintain plain but respectable English
- The formal document should be organized and official in tone
- The email version should be shorter and easier to read
- Include: incident summary, timeline, sender/contact details, what was shared, amount lost, actions taken, evidence list, likely fraud category

Return ONLY valid JSON:
{
  "doc_title": "Cyber Crime Complaint — Case XXXX",
  "doc_body": "Full complaint text with sections",
  "email_subject": "Cyber incident summary — Case XXXX",
  "email_body": "Shorter email-friendly summary text"
}
"""


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------

class ChatSession:
    """Manages state for a single user chat session."""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id or str(uuid.uuid4())
        self.messages: list[dict[str, Any]] = []  # [{role, content, timestamp}]
        self.case_state: dict[str, Any] = {
            "risk_stage": None,           # safe_exposure | clicked_no_share | shared_details | financial_loss
            "likely_scam_type": None,
            "risk_level": None,
            "confidence": 0,
            "signals_found": [],
            "action_steps": [],
            "input_modality": None,       # text | image | audio | apk
            "questions_asked": [],
            "answers_received": {},
            "golden_hour_active": False,
            "golden_hour_triggered": False,
            "minutes_since_loss": None,
            "amount_lost": None,
            "detailed_story_requested": False,
            "detailed_story_received": False,
            "doc_created": False,
            "gmail_created": False,
            "calendar_created": False,
            "tasks_created": False,
        }
        self.case_id = f"SATARK-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    def add_message(self, role: str, content: str) -> None:
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def get_conversation_for_model(self) -> list:
        """Build a Gemini-compatible conversation history."""
        contents = []
        for msg in self.messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append(types.Content(
                role=role,
                parts=[types.Part(text=msg["content"])],
            ))
        return contents


def _call_model(system_prompt: str, user_text: str, history: list | None = None) -> str:
    """Single-turn or multi-turn call to Gemini."""
    contents = list(history) if history else []
    contents.append(types.Content(
        role="user",
        parts=[types.Part(text=user_text)],
    ))
    resp = _client.models.generate_content(
        model=MODEL_FLASH,
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.4,
            thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
        ),
    )
    return _response_text(resp)


def _call_model_json(system_prompt: str, user_text: str) -> dict:
    """Call model expecting JSON output."""
    resp = _client.models.generate_content(
        model=MODEL_FLASH,
        contents=[types.Content(role="user", parts=[types.Part(text=user_text)])],
        config=types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.2,
            thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
            response_mime_type="application/json",
        ),
    )
    return _parse_json(_response_text(resp))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def handle_chat_message(
    session: ChatSession,
    user_text: str,
    *,
    files: list[dict] | None = None,
    modality_hint: str | None = None,
    google_credentials: Any | None = None,
) -> dict[str, Any]:
    """Process a user message and return the assistant response.

    This is the main orchestration function. It:
    1. Records the message
    2. Builds context from conversation history
    3. Decides whether to ask MCQs or assess
    4. If assessing, determines risk stage
    5. If golden hour, triggers integrations
    6. Returns the response to show the user
    """
    session.add_message("user", user_text)

    # Detect modality
    modality = modality_hint or "text"
    if files:
        for f in files:
            ft = (f.get("file_type") or "").lower()
            if "apk" in ft or (f.get("file_name") or "").endswith(".apk"):
                modality = "apk"
                break
            elif "audio" in ft:
                modality = "audio"
                break
            elif "image" in ft or "png" in ft or "jpg" in ft or "jpeg" in ft:
                modality = "image"
                break
    session.case_state["input_modality"] = modality

    # Build the full context for the model
    context_summary = _build_context_summary(session, files)

    # Step 1: Ask the manager to triage
    raw = _call_model(
        MANAGER_SYSTEM_PROMPT,
        context_summary,
        history=session.get_conversation_for_model()[:-1],  # all except current
    )

    parsed = _parse_json(raw)
    action = parsed.get("action", "")

    # If model wants to ask questions
    if action == "ask_questions":
        questions = parsed.get("questions", [])
        session.case_state["questions_asked"].extend(questions)

        # Build a natural question message
        question_text = _format_questions_as_chat(questions)
        session.add_message("assistant", question_text)

        return {
            "type": "questions",
            "case_id": session.case_id,
            "chat_reply": question_text,
            "questions": questions,
            "session_id": session.session_id,
        }

    # If model has enough info to assess
    if action == "assess":
        return await _handle_assessment(session, parsed, google_credentials)

    # Fallback: model gave a free-form reply (no JSON action)
    if raw.strip() and not parsed:
        session.add_message("assistant", raw.strip())
        return {
            "type": "reply",
            "case_id": session.case_id,
            "chat_reply": raw.strip(),
            "session_id": session.session_id,
        }

    # If we got JSON but no recognized action, try to extract chat_reply
    chat_reply = parsed.get("chat_reply", raw.strip() or "I need a bit more information. Could you tell me more about what happened?")
    session.add_message("assistant", chat_reply)
    return {
        "type": "reply",
        "case_id": session.case_id,
        "chat_reply": chat_reply,
        "session_id": session.session_id,
    }


async def handle_mcq_answer(
    session: ChatSession,
    answers: dict[str, str],
    *,
    google_credentials: Any | None = None,
) -> dict[str, Any]:
    """Process user's answers to MCQ questions and continue the flow."""
    session.case_state["answers_received"].update(answers)

    # Format answers as natural text
    answer_text = "\n".join(f"- {qid}: {ans}" for qid, ans in answers.items())
    session.add_message("user", f"My answers:\n{answer_text}")

    # Ask manager to reassess with the new info
    context_summary = _build_context_summary(session)
    raw = _call_model(
        MANAGER_SYSTEM_PROMPT,
        context_summary,
        history=session.get_conversation_for_model()[:-1],
    )

    parsed = _parse_json(raw)
    action = parsed.get("action", "")

    if action == "ask_questions":
        questions = parsed.get("questions", [])
        session.case_state["questions_asked"].extend(questions)
        question_text = _format_questions_as_chat(questions)
        session.add_message("assistant", question_text)
        return {
            "type": "questions",
            "case_id": session.case_id,
            "chat_reply": question_text,
            "questions": questions,
            "session_id": session.session_id,
        }

    if action == "assess":
        return await _handle_assessment(session, parsed, google_credentials)

    chat_reply = parsed.get("chat_reply", raw.strip())
    session.add_message("assistant", chat_reply)
    return {
        "type": "reply",
        "case_id": session.case_id,
        "chat_reply": chat_reply,
        "session_id": session.session_id,
    }


async def handle_detailed_story(
    session: ChatSession,
    story_text: str,
    *,
    google_credentials: Any | None = None,
) -> dict[str, Any]:
    """Process the user's detailed incident narrative and generate artifacts."""
    session.add_message("user", story_text)
    session.case_state["detailed_story_received"] = True

    # Generate complaint doc + email content
    case_context = json.dumps({
        "case_id": session.case_id,
        "scam_type": session.case_state.get("likely_scam_type"),
        "risk_stage": session.case_state.get("risk_stage"),
        "amount_lost": session.case_state.get("amount_lost"),
        "minutes_since_loss": session.case_state.get("minutes_since_loss"),
        "signals": session.case_state.get("signals_found", []),
        "user_story": story_text,
        "conversation_summary": _summarize_conversation(session),
    }, indent=2)

    doc_data = _call_model_json(
        COMPLAINT_DOC_PROMPT,
        f"Generate the complaint document and email summary for this case:\n\n{case_context}",
    )

    result: dict[str, Any] = {
        "type": "artifacts",
        "case_id": session.case_id,
        "session_id": session.session_id,
        "doc_created": False,
        "gmail_created": False,
    }

    # Create Google Doc if credentials available
    if google_credentials and doc_data.get("doc_body"):
        try:
            from tools.google_workspace import create_case_report_doc
            doc_result = create_case_report_doc(
                google_credentials,
                case_id=session.case_id,
                title=doc_data.get("doc_title", f"Cyber Crime Complaint — {session.case_id}"),
                report_text=doc_data["doc_body"],
            )
            result["doc_created"] = doc_result.get("created", False)
            result["doc_url"] = doc_result.get("doc_url", "")
            session.case_state["doc_created"] = result["doc_created"]
        except Exception as e:
            logger.warning("Doc creation failed: %s", e)
            result["doc_error"] = str(e)

    # Create Gmail draft if credentials available
    if google_credentials and doc_data.get("email_body"):
        try:
            from tools.google_workspace import create_gmail_draft
            # Get user email from credentials or session
            user_email = ""
            if hasattr(google_credentials, "token"):
                # Try to get from session state
                user_email = session.case_state.get("user_email", "")

            gmail_result = create_gmail_draft(
                google_credentials,
                to_email=user_email,
                subject=doc_data.get("email_subject", f"Cyber incident summary — {session.case_id}"),
                body_text=doc_data["email_body"] + (f"\n\nComplaint document: {result.get('doc_url', '')}" if result.get("doc_url") else ""),
            )
            result["gmail_created"] = gmail_result.get("created", False)
            result["draft_url"] = gmail_result.get("draft_url", "")
            session.case_state["gmail_created"] = result["gmail_created"]
        except Exception as e:
            logger.warning("Gmail draft failed: %s", e)
            result["gmail_error"] = str(e)

    # Build the chat reply about created artifacts
    artifact_reply = _build_artifact_reply(result, doc_data)
    session.add_message("assistant", artifact_reply)
    result["chat_reply"] = artifact_reply

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_context_summary(session: ChatSession, files: list[dict] | None = None) -> str:
    """Build a context block for the model from session state."""
    parts = []
    parts.append(f"Case ID: {session.case_id}")
    parts.append(f"Input modality: {session.case_state.get('input_modality', 'text')}")

    if session.case_state["answers_received"]:
        parts.append("\nUser's answers to previous questions:")
        for qid, ans in session.case_state["answers_received"].items():
            parts.append(f"  - {qid}: {ans}")

    if session.case_state["risk_stage"]:
        parts.append(f"\nCurrent risk assessment: {session.case_state['risk_stage']}")

    if files:
        parts.append("\nAttached files:")
        for f in files:
            parts.append(f"  - {f.get('file_name', 'unknown')} ({f.get('file_type', 'unknown')})")
            if f.get("extracted_text"):
                parts.append(f"    Extracted text: {f['extracted_text'][:500]}")
            if f.get("apk_analysis"):
                parts.append(f"    APK analysis: {json.dumps(f['apk_analysis'], indent=2)[:800]}")

    # Include the latest user message explicitly
    if session.messages:
        last_user = [m for m in session.messages if m["role"] == "user"]
        if last_user:
            parts.append(f"\nUser's latest message: {last_user[-1]['content']}")

    parts.append("\nBased on the full conversation and context above, decide: do you need to ask clarification questions (action: ask_questions), or do you have enough to assess (action: assess)?")

    return "\n".join(parts)


def _format_questions_as_chat(questions: list[dict]) -> str:
    """Convert structured questions into a natural chat message."""
    if not questions:
        return "Could you tell me a bit more about what happened?"

    lines = ["I need to understand your situation better. Could you quickly answer these:"]
    for i, q in enumerate(questions, 1):
        opts = q.get("options", [])
        if opts:
            opt_str = " / ".join(str(o) for o in opts)
            lines.append(f"\n{i}. {q.get('text', '')}  ({opt_str})")
        else:
            lines.append(f"\n{i}. {q.get('text', '')}")
    return "\n".join(lines)


async def _handle_assessment(
    session: ChatSession,
    parsed: dict,
    google_credentials: Any | None,
) -> dict[str, Any]:
    """Handle a completed risk assessment and trigger workflows if needed."""
    # Update case state
    session.case_state["risk_stage"] = parsed.get("risk_stage")
    session.case_state["likely_scam_type"] = parsed.get("likely_scam_type")
    session.case_state["risk_level"] = parsed.get("risk_level")
    session.case_state["confidence"] = parsed.get("confidence", 0)
    session.case_state["signals_found"] = parsed.get("signals_found", [])
    session.case_state["action_steps"] = parsed.get("action_steps", [])

    chat_reply = parsed.get("chat_reply", "")
    needs_golden_hour = parsed.get("needs_golden_hour", False)
    needs_detailed_story = parsed.get("needs_detailed_story", False)

    result: dict[str, Any] = {
        "type": "assessment",
        "case_id": session.case_id,
        "session_id": session.session_id,
        "risk_stage": session.case_state["risk_stage"],
        "risk_level": session.case_state["risk_level"],
        "likely_scam_type": session.case_state["likely_scam_type"],
        "confidence": session.case_state["confidence"],
        "signals_found": session.case_state["signals_found"],
        "action_steps": session.case_state["action_steps"],
    }

    # Golden hour flow — always trigger for financial_loss
    if session.case_state["risk_stage"] == "financial_loss" and not session.case_state.get("golden_hour_triggered"):
        golden_result = await _trigger_golden_hour(session, google_credentials)
        result.update(golden_result)

        # Append golden hour info to chat reply
        if golden_result.get("golden_hour_chat"):
            chat_reply = chat_reply + "\n\n" + golden_result["golden_hour_chat"]

    session.add_message("assistant", chat_reply)
    result["chat_reply"] = chat_reply

    # If we need to ask for detailed story (sent as separate follow-up)
    if needs_detailed_story or session.case_state["risk_stage"] == "financial_loss":
        session.case_state["detailed_story_requested"] = True
        result["needs_detailed_story"] = True

    return result


async def _trigger_golden_hour(
    session: ChatSession,
    google_credentials: Any | None,
) -> dict[str, Any]:
    """Plan and execute golden hour actions."""
    result: dict[str, Any] = {
        "golden_hour_active": True,
        "calendar_created": False,
        "tasks_created": False,
    }

    minutes_since = session.case_state.get("minutes_since_loss")
    amount_lost = session.case_state.get("amount_lost")

    # Get the golden hour plan from the model
    plan_context = json.dumps({
        "case_id": session.case_id,
        "scam_type": session.case_state.get("likely_scam_type"),
        "minutes_since_loss": minutes_since,
        "amount_lost": amount_lost,
        "what_was_shared": session.case_state.get("answers_received", {}),
        "signals": session.case_state.get("signals_found", []),
    }, indent=2)

    plan = _call_model_json(
        GOLDEN_HOUR_PLANNER_PROMPT,
        f"Create an urgent golden hour action plan:\n\n{plan_context}",
    )

    result["golden_hour_plan"] = plan
    result["golden_hour_chat"] = plan.get("chat_summary", "")

    session.case_state["golden_hour_active"] = True
    session.case_state["golden_hour_triggered"] = True

    # Create Google Calendar events
    if google_credentials:
        try:
            from tools.google_workspace import create_golden_hour_calendar_events
            cal_result = create_golden_hour_calendar_events(
                google_credentials,
                case_id=session.case_id,
                scam_type=session.case_state.get("likely_scam_type", "Cyber Fraud"),
                minutes_elapsed=minutes_since,
            )
            result["calendar_created"] = cal_result.get("created", False)
            result["calendar_events"] = cal_result.get("events", [])
            result["calendar_url"] = cal_result.get("event_url", "")
            session.case_state["calendar_created"] = result["calendar_created"]
        except Exception as e:
            logger.warning("Calendar creation failed: %s", e)
            result["calendar_error"] = str(e)

        # Create Google Tasks
        try:
            from tools.google_workspace import create_golden_hour_tasks
            tasks_result = create_golden_hour_tasks(
                google_credentials,
                case_id=session.case_id,
                scam_type=session.case_state.get("likely_scam_type", "Cyber Fraud"),
                complaint_text=plan.get("chat_summary", ""),
            )
            result["tasks_created"] = tasks_result.get("created", False)
            result["tasks_count"] = tasks_result.get("tasks_created", 0)
            result["task_url"] = tasks_result.get("task_url", "")
            session.case_state["tasks_created"] = result["tasks_created"]
        except Exception as e:
            logger.warning("Tasks creation failed: %s", e)
            result["tasks_error"] = str(e)

    return result


def _build_artifact_reply(result: dict, doc_data: dict) -> str:
    """Build a natural reply about created artifacts."""
    parts = []

    if result.get("doc_created") and result.get("doc_url"):
        parts.append(f"I have prepared your complaint document. You can view and download it here:\n{result['doc_url']}")
        parts.append("The document is ready to share with the cybercrime police station when you visit.")
    elif doc_data.get("doc_body"):
        parts.append("I prepared the complaint text but could not create the Google Doc. You can copy it from the chat.")

    if result.get("gmail_created") and result.get("draft_url"):
        parts.append(f"\nI have also saved a summary in your Gmail drafts:\n{result['draft_url']}")
    elif result.get("gmail_created"):
        parts.append("\nA summary has been saved in your Gmail drafts.")

    if not parts:
        parts.append("I have prepared your case summary. Let me know if you need anything else.")

    return "\n\n".join(parts)


def _summarize_conversation(session: ChatSession) -> str:
    """Create a brief conversation summary for document generation."""
    lines = []
    for msg in session.messages[-20:]:
        role_label = "User" if msg["role"] == "user" else "SATARK"
        lines.append(f"{role_label}: {msg['content'][:300]}")
    return "\n".join(lines)
