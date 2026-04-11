"""
Chat API — the primary user-facing endpoints.

Implements the conversational flow:
  POST /api/chat/message      — send text/files, get reply or MCQs
  POST /api/chat/answer       — answer MCQ follow-ups
  POST /api/chat/story        — provide detailed incident narrative
  GET  /api/chat/session/{id} — get full session state
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Cookie, HTTPException, Request
from pydantic import BaseModel, Field

from agents.chat_orchestrator.orchestrator import (
    ChatSession,
    handle_chat_message,
    handle_detailed_story,
    handle_mcq_answer,
)

logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/api/chat", tags=["chat"])

# In-memory session store (production: Firestore-backed)
_SESSIONS: dict[str, ChatSession] = {}


def _get_or_create_session(session_id: str | None) -> ChatSession:
    if session_id and session_id in _SESSIONS:
        return _SESSIONS[session_id]
    s = ChatSession(session_id=session_id)
    _SESSIONS[s.session_id] = s
    return s


def _get_google_credentials(request: Request, session: ChatSession) -> Any | None:
    """Try to build Google OAuth credentials from the user's session."""
    try:
        from db.sessions_repo import get_google_oauth
        from tools.google_workspace import build_google_credentials

        # Try cookie first, then the chat session's own session_id
        sid = request.cookies.get("session_id") or session.session_id
        oauth_data = get_google_oauth(sid)
        if not oauth_data:
            # Also try the chat session ID if cookie was different
            if sid != session.session_id:
                oauth_data = get_google_oauth(session.session_id)
        if oauth_data:
            creds = build_google_credentials(oauth_data)
            if creds:
                # Capture email for later use
                if oauth_data.get("email"):
                    session.case_state["user_email"] = oauth_data["email"]
                logger.info("Google credentials loaded for session %s", sid)
                return creds
            else:
                logger.warning("build_google_credentials returned None for session %s", sid)
        else:
            logger.debug("No OAuth data found for session %s", sid)
    except Exception as e:
        logger.warning("Could not load Google credentials: %s", e)
    return None


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class FileAttachment(BaseModel):
    file_name: str = ""
    file_type: str = ""
    content_base64: str = ""
    extracted_text: str | None = None
    apk_analysis: dict | None = None


class ChatMessageRequest(BaseModel):
    session_id: str | None = None
    message: str = ""
    files: list[FileAttachment] = Field(default_factory=list)


class MCQAnswerRequest(BaseModel):
    session_id: str
    answers: dict[str, str]  # {question_id: answer_value}


class DetailedStoryRequest(BaseModel):
    session_id: str
    story: str


class ChatResponse(BaseModel):
    session_id: str
    case_id: str
    type: str  # "questions" | "assessment" | "reply" | "artifacts"
    chat_reply: str
    questions: list[dict] | None = None
    risk_stage: str | None = None
    risk_level: str | None = None
    likely_scam_type: str | None = None
    confidence: int | None = None
    signals_found: list[str] | None = None
    action_steps: list[str] | None = None
    needs_detailed_story: bool = False
    golden_hour_active: bool = False
    calendar_created: bool = False
    tasks_created: bool = False
    calendar_url: str | None = None
    task_url: str | None = None
    doc_created: bool = False
    doc_url: str | None = None
    gmail_created: bool = False
    draft_url: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/message", response_model=ChatResponse)
async def chat_message(req: ChatMessageRequest, request: Request):
    """Send a message (text, screenshot, audio, APK) and get a response."""
    session = _get_or_create_session(req.session_id)
    creds = _get_google_credentials(request, session)

    files = [f.model_dump() for f in req.files] if req.files else None

    result = await handle_chat_message(
        session,
        req.message,
        files=files,
        google_credentials=creds,
    )

    return ChatResponse(
        session_id=session.session_id,
        case_id=result.get("case_id", session.case_id),
        type=result.get("type", "reply"),
        chat_reply=result.get("chat_reply", ""),
        questions=result.get("questions"),
        risk_stage=result.get("risk_stage"),
        risk_level=result.get("risk_level"),
        likely_scam_type=result.get("likely_scam_type"),
        confidence=result.get("confidence"),
        signals_found=result.get("signals_found"),
        action_steps=result.get("action_steps"),
        needs_detailed_story=result.get("needs_detailed_story", False),
        golden_hour_active=result.get("golden_hour_active", False),
        calendar_created=result.get("calendar_created", False),
        tasks_created=result.get("tasks_created", False),
        calendar_url=result.get("calendar_url"),
        task_url=result.get("task_url"),
        doc_created=result.get("doc_created", False),
        doc_url=result.get("doc_url"),
        gmail_created=result.get("gmail_created", False),
        draft_url=result.get("draft_url"),
    )


@router.post("/answer", response_model=ChatResponse)
async def chat_answer(req: MCQAnswerRequest, request: Request):
    """Answer follow-up MCQ questions."""
    if req.session_id not in _SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")

    session = _SESSIONS[req.session_id]
    creds = _get_google_credentials(request, session)

    result = await handle_mcq_answer(
        session,
        req.answers,
        google_credentials=creds,
    )

    return ChatResponse(
        session_id=session.session_id,
        case_id=result.get("case_id", session.case_id),
        type=result.get("type", "reply"),
        chat_reply=result.get("chat_reply", ""),
        questions=result.get("questions"),
        risk_stage=result.get("risk_stage"),
        risk_level=result.get("risk_level"),
        likely_scam_type=result.get("likely_scam_type"),
        confidence=result.get("confidence"),
        signals_found=result.get("signals_found"),
        action_steps=result.get("action_steps"),
        needs_detailed_story=result.get("needs_detailed_story", False),
        golden_hour_active=result.get("golden_hour_active", False),
        calendar_created=result.get("calendar_created", False),
        tasks_created=result.get("tasks_created", False),
        calendar_url=result.get("calendar_url"),
        task_url=result.get("task_url"),
    )


@router.post("/story", response_model=ChatResponse)
async def chat_story(req: DetailedStoryRequest, request: Request):
    """Provide detailed incident narrative for document generation."""
    if req.session_id not in _SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")

    session = _SESSIONS[req.session_id]
    creds = _get_google_credentials(request, session)

    result = await handle_detailed_story(
        session,
        req.story,
        google_credentials=creds,
    )

    return ChatResponse(
        session_id=session.session_id,
        case_id=result.get("case_id", session.case_id),
        type=result.get("type", "artifacts"),
        chat_reply=result.get("chat_reply", ""),
        doc_created=result.get("doc_created", False),
        doc_url=result.get("doc_url"),
        gmail_created=result.get("gmail_created", False),
        draft_url=result.get("draft_url"),
    )


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get full session state and conversation history."""
    if session_id not in _SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")

    session = _SESSIONS[session_id]
    return {
        "session_id": session.session_id,
        "case_id": session.case_id,
        "messages": session.messages,
        "case_state": session.case_state,
    }
