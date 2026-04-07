import os, sys
import warnings

warnings.filterwarnings(
    "ignore",
    message=".*non-text parts in the response.*",
)

# requests_oauthlib can raise if Google returns expanded scope URLs (e.g.
# https://www.googleapis.com/auth/userinfo.profile) while the flow was
# initialized with shorthand (e.g. profile/email). Relaxing scope matching is
# the recommended fix for this behavior.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")
import asyncio
import json
import mimetypes
import uuid
import logging
import re
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi import Cookie, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel, Field
from typing import Any, Optional
import uvicorn
from agents.manager import run_pipeline
from agents.manager.agent import run as run_legacy_pipeline
from db.operations import (
    find_similar_patterns,
    get_fraud_patterns_count,
    get_fraud_patterns_count_by_type,
    get_case_stats,
    save_case,
    save_fraud_pattern,
)
from db.client import get_db
from fastapi.staticfiles import StaticFiles
import base64
from urllib.parse import urlparse
from config import PROJECT_ID, LOCATION, GEMINI_LIVE_MODEL
from api.workflow_api import router as workflow_router

from db.sessions_repo import (
    set_google_oauth,
    set_google_oauth_pkce,
    get_google_oauth,
    get_google_oauth_pkce,
    clear_google_oauth_pkce,
    clear_google_oauth,
)

logger = logging.getLogger("uvicorn.error")

try:
    from google import genai
    from google.genai import types as genai_types
except Exception:
    genai = None  # type: ignore
    genai_types = None  # type: ignore


LIVE_STREAM_INSTRUCTION = (
    "You are SATARK AI, a real-time cyber fraud analyst. "
    "As live audio arrives, return concise TEXT updates with: "
    "RISK (SAFE|MEDIUM|HIGH|CRITICAL), likely scam type, and immediate next action. "
    "Do not force escalation unless concrete compromise evidence is present."
)


live_client = (
    genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    if genai is not None
    else None
)

app = FastAPI(
    title="SATARK AI",
    description="Smart Anti-fraud Technology for Awareness, Reporting & Knowledge",
    version="1.0.0"
)

app.include_router(workflow_router)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/ui")
def serve_ui():
    preferred = "frontend/satark-ui-v2.html"
    if os.path.exists(preferred):
        return FileResponse(preferred)
    return FileResponse("frontend/ui.html")


@app.get("/ops")
def serve_ops():
    return FileResponse("frontend/index.html")


@app.get("/")
def serve_root_ui():
    preferred = "frontend/satark-ui-v2.html"
    if os.path.exists(preferred):
        return FileResponse(preferred)
    return FileResponse("frontend/ui.html")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


def _public_base_url(request: Request) -> str:
    explicit = os.getenv("SATARK_PUBLIC_BASE_URL")
    if explicit:
        return explicit.rstrip("/")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def _is_safe_relative_path(path: str) -> bool:
    path = str(path or "")
    if not path.startswith("/"):
        return False
    parsed = urlparse(path)
    return not parsed.scheme and not parsed.netloc


def _sign_state(payload: dict[str, Any]) -> str:
    import hmac
    import hashlib

    secret = (os.getenv("SATARK_AUTH_STATE_SECRET") or "dev-insecure-change-me").encode("utf-8")
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    mac = hmac.new(secret, b64.encode("utf-8"), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")
    return f"{b64}.{sig}"


def _unsign_state(state: str) -> dict[str, Any] | None:
    import hmac
    import hashlib

    try:
        b64, sig = state.split(".", 1)
    except ValueError:
        return None

    secret = (os.getenv("SATARK_AUTH_STATE_SECRET") or "dev-insecure-change-me").encode("utf-8")
    mac = hmac.new(secret, b64.encode("utf-8"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")
    if not hmac.compare_digest(expected, sig):
        return None

    padded = b64 + "=" * (-len(b64) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
    payload = json.loads(raw.decode("utf-8"))
    return payload if isinstance(payload, dict) else None


def _google_oauth_client_config() -> dict[str, Any]:
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        missing = []
        if not client_id:
            missing.append("GOOGLE_CLIENT_ID")
        if not client_secret:
            missing.append("GOOGLE_CLIENT_SECRET")
        raise HTTPException(status_code=500, detail={"error": "oauth_config_missing", "missing": missing})
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def _safe_account_id(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "normal"
    raw = re.sub(r"[^a-z0-9_-]+", "_", raw)
    raw = raw.strip("_-")
    return (raw or "normal")[:64]


def _try_write_calendar_mcp_tokens_from_oauth(session_id: str, oauth_payload: dict[str, Any]) -> tuple[str | None, str | None]:
    """Best-effort: write a tokens JSON compatible with @cocal/google-calendar-mcp.

    Returns (token_path, account_id) when successful, else (None, None).
    """
    try:
        from pathlib import Path

        account_id = _safe_account_id(session_id)
        cfg_dir = Path(os.getenv("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        token_dir = cfg_dir / "satark-ai" / "google-calendar-mcp"
        token_dir.mkdir(parents=True, exist_ok=True)
        token_path = token_dir / f"tokens.{account_id}.json"

        token_payload: dict[str, Any] = {}
        access_token = oauth_payload.get("access_token")
        refresh_token = oauth_payload.get("refresh_token")
        scopes = oauth_payload.get("scopes")
        expiry = oauth_payload.get("expiry")

        if access_token:
            token_payload["access_token"] = str(access_token)
        if refresh_token:
            token_payload["refresh_token"] = str(refresh_token)
        if isinstance(scopes, list) and scopes:
            token_payload["scope"] = " ".join(str(s) for s in scopes if s)
        if expiry:
            try:
                iso = str(expiry)
                if iso.endswith("Z"):
                    iso = iso[:-1] + "+00:00"
                dt = datetime.fromisoformat(iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                token_payload["expiry_date"] = int(dt.timestamp() * 1000)
            except Exception:
                pass

        if not token_payload:
            return None, None

        multi = {account_id: token_payload}
        tmp = token_path.with_suffix(token_path.suffix + ".tmp")
        tmp.write_text(json.dumps(multi, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        tmp.replace(token_path)
        try:
            os.chmod(token_path, 0o600)
        except Exception:
            pass

        return str(token_path), account_id
    except Exception:
        return None, None


# Temporary PKCE verifier cache for environments without Firestore.
# Keyed by OAuth `state`. Callback should be within a few minutes.
_OAUTH_PKCE_CACHE: dict[str, dict[str, Any]] = {}


def _pkce_cache_put(state: str, session_id: str, code_verifier: str | None) -> None:
    if not state or not code_verifier:
        return
    _OAUTH_PKCE_CACHE[state] = {
        "session_id": session_id,
        "code_verifier": code_verifier,
        "created_at": datetime.now(timezone.utc).timestamp(),
    }


def _pkce_cache_get(state: str) -> str | None:
    if not state:
        return None
    row = _OAUTH_PKCE_CACHE.get(state)
    if not isinstance(row, dict):
        return None
    return str(row.get("code_verifier") or "") or None


def _pkce_cache_del(state: str) -> None:
    if state:
        _OAUTH_PKCE_CACHE.pop(state, None)


def _pkce_cache_prune(max_age_seconds: int = 900) -> None:
    try:
        now = datetime.now(timezone.utc).timestamp()
        stale = [
            k
            for k, v in _OAUTH_PKCE_CACHE.items()
            if not isinstance(v, dict) or (now - float(v.get("created_at") or 0)) > max_age_seconds
        ]
        for k in stale:
            _OAUTH_PKCE_CACHE.pop(k, None)
    except Exception:
        return


@app.get("/auth/google/start")
def auth_google_start(request: Request, session_id: str, next: str = "/ui"):
    if not session_id or len(session_id) < 6:
        raise HTTPException(status_code=400, detail="session_id required")

    next_path = next if _is_safe_relative_path(next) else "/ui"
    redirect_uri = f"{_public_base_url(request)}/auth/google/callback"
    scopes = [
        "https://www.googleapis.com/auth/calendar.events",
        "https://www.googleapis.com/auth/tasks",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/documents",
        "openid",
        "email",
        "profile",
    ]

    required = {
        "GOOGLE_CLIENT_ID": os.getenv("GOOGLE_CLIENT_ID"),
        "GOOGLE_CLIENT_SECRET": os.getenv("GOOGLE_CLIENT_SECRET"),
        "SATARK_AUTH_STATE_SECRET": os.getenv("SATARK_AUTH_STATE_SECRET"),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        logger.warning("google_oauth.start missing_env=%s redirect_uri=%s", missing, redirect_uri)
        raise HTTPException(
            status_code=500,
            detail={"error": "oauth_config_missing", "missing": missing, "redirect_uri": redirect_uri},
        )

    logger.info("google_oauth.start redirect_uri=%s next=%s", redirect_uri, next_path)

    try:
        from google_auth_oauthlib.flow import Flow
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"google-auth-oauthlib not available: {e}")

    state = _sign_state({"sid": session_id, "next": next_path})
    flow = Flow.from_client_config(_google_oauth_client_config(), scopes=scopes, state=state)
    flow.redirect_uri = redirect_uri

    authorization_url, returned_state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    verifier = getattr(flow, "code_verifier", None)
    _pkce_cache_prune()
    _pkce_cache_put(returned_state or state, session_id, verifier)
    set_google_oauth_pkce(
        session_id,
        {
            "state": returned_state or state,
            "code_verifier": verifier,
            "next": next_path,
            "redirect_uri": redirect_uri,
        },
    )
    return RedirectResponse(url=authorization_url)


@app.get("/auth/google/callback")
def auth_google_callback(request: Request, code: str | None = None, state: str | None = None):
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")

    if not os.getenv("SATARK_AUTH_STATE_SECRET"):
        raise HTTPException(status_code=500, detail={"error": "oauth_config_missing", "missing": ["SATARK_AUTH_STATE_SECRET"]})

    state_payload = _unsign_state(state)
    if not state_payload:
        raise HTTPException(status_code=400, detail="Invalid state")

    session_id = str(state_payload.get("sid") or "")
    next_path = str(state_payload.get("next") or "/ui")
    if not _is_safe_relative_path(next_path):
        next_path = "/ui"

    redirect_uri = f"{_public_base_url(request)}/auth/google/callback"
    scopes = [
        "https://www.googleapis.com/auth/calendar.events",
        "https://www.googleapis.com/auth/tasks",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/documents",
        "openid",
        "email",
        "profile",
    ]

    logger.info("google_oauth.callback redirect_uri=%s", redirect_uri)

    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_config(_google_oauth_client_config(), scopes=scopes, state=state)
    flow.redirect_uri = redirect_uri

    code_verifier: str | None = None
    try:
        pkce = get_google_oauth_pkce(session_id)
        if isinstance(pkce, dict) and str(pkce.get("state") or "") == str(state or ""):
            code_verifier = str(pkce.get("code_verifier") or "") or None
    except Exception:
        code_verifier = None

    if not code_verifier:
        code_verifier = _pkce_cache_get(str(state or ""))

    try:
        if code_verifier:
            flow.fetch_token(code=code, code_verifier=code_verifier)
        else:
            flow.fetch_token(code=code)
    except Exception as e:
        logger.exception("google_oauth.callback token_exchange_failed")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "pkce_verifier_missing" if not code_verifier else "token_exchange_failed",
                "message": str(e),
            },
        )
    creds = flow.credentials

    oauth_payload = {
        "access_token": getattr(creds, "token", None),
        "refresh_token": getattr(creds, "refresh_token", None),
        "scopes": list(getattr(creds, "scopes", []) or []),
        "expiry": getattr(creds, "expiry", None).isoformat() if getattr(creds, "expiry", None) else None,
    }

    # Best-effort: write a google-calendar-mcp compatible token file so Golden Hour can
    # run non-interactively. This path is persisted alongside the OAuth tokens.
    token_path, account_id = _try_write_calendar_mcp_tokens_from_oauth(session_id, oauth_payload)
    if token_path:
        oauth_payload["calendar_mcp_token_path"] = token_path
    if account_id:
        oauth_payload["calendar_mcp_account_id"] = account_id

    # Best-effort: capture the Google account email for UI display.
    try:
        import urllib.request

        token = getattr(creds, "token", None)
        if token:
            req = urllib.request.Request(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec - controlled Google endpoint
                data = json.loads(resp.read().decode("utf-8") or "{}")
            email = str(data.get("email") or "").strip()
            if email:
                oauth_payload["email"] = email
    except Exception:
        pass

    if not set_google_oauth(session_id, oauth_payload):
        raise HTTPException(status_code=500, detail="Could not persist Google OAuth tokens")

    clear_google_oauth_pkce(session_id)
    _pkce_cache_del(str(state or ""))

    joiner = "&" if "?" in next_path else "?"
    response = RedirectResponse(url=f"{next_path}{joiner}google=connected")
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30,
    )
    return response


@app.get("/api/auth/status")
def auth_status(session_id: str | None = Cookie(default=None)):
    if not session_id:
        return {"connected": False, "email": None}
    oauth = get_google_oauth(session_id)
    if not oauth:
        return {"connected": False, "email": None}

    has_tokens = bool(oauth.get("refresh_token") or oauth.get("access_token"))
    email = oauth.get("email") if isinstance(oauth.get("email"), str) else None
    return {"connected": has_tokens, "email": email}


@app.get("/auth/google/logout")
def auth_google_logout(response: Response, session_id: str | None = Cookie(default=None)):
    if session_id:
        clear_google_oauth(session_id)
    redirect = RedirectResponse("/ui")
    redirect.delete_cookie("session_id")
    return redirect


class AnalyzeFile(BaseModel):
    file_name: str
    file_type: Optional[str] = None
    file_url: Optional[str] = None
    content_base64: Optional[str] = None


class AnalyzeUserInput(BaseModel):
    text: str = ""
    language_hint: Optional[str] = None
    files: list[AnalyzeFile] = Field(default_factory=list)


class AnalyzeUserContext(BaseModel):
    location: Optional[str] = None
    channel: str = "web-ui"
    locale: str = "en-IN"


class AnalyzeOptions(BaseModel):
    stream: bool = True
    generate_report: bool = True
    trigger_mcp_actions: bool = False
    recovery_answers: dict[str, Any] = Field(default_factory=dict)
    preprocessed_context: dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequestV1(BaseModel):
    session_id: Optional[str] = None
    user_input: AnalyzeUserInput
    user_context: AnalyzeUserContext = Field(default_factory=AnalyzeUserContext)
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


class PreprocessRequest(BaseModel):
    session_id: Optional[str] = None
    user_input: AnalyzeUserInput


class RecoveryFinalizeRequest(BaseModel):
    run_id: str
    did_lose_money_or_share_bank_details: bool
    amount_lost: Optional[float] = 0
    time_bucket: Optional[str] = None
    explicit_report_request: bool = False


RUN_STORE: dict[str, dict] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _normalize_agent(agent: str) -> str:
    alias = {
        "manager": "manager",
        "scam": "scam_detector",
        "scam_detector": "scam_detector",
        "audio": "audio_analyzer",
        "audio_analyzer": "audio_analyzer",
        "apk": "apk_analyzer",
        "apk_analyzer": "apk_analyzer",
        "osint": "osint",
        "golden": "golden_hour",
        "golden_hour": "golden_hour",
    }
    return alias.get(agent, agent)


def _classify_flow(user_input: dict) -> tuple[str, list[str], list[tuple[str, str]]]:
    files = user_input.get("files") or []
    text = str(user_input.get("text") or "").lower()

    def _is_audio(file_item: dict) -> bool:
        ft = str(file_item.get("file_type") or "")
        fn = str(file_item.get("file_name") or "")
        return ft.startswith("audio/") or fn.lower().endswith((".mp3", ".wav", ".m4a", ".ogg"))

    def _is_apk(file_item: dict) -> bool:
        ft = str(file_item.get("file_type") or "")
        fn = str(file_item.get("file_name") or "")
        return ft == "application/vnd.android.package-archive" or fn.lower().endswith(".apk")

    has_audio = any(_is_audio(f) for f in files)
    has_apk = any(_is_apk(f) for f in files)
    has_image = any(str(f.get("file_type") or "").startswith("image/") for f in files)
    
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    has_url = bool(url_pattern.search(text))

    primary_type = "text"
    if has_audio and has_apk:
        primary_type = "audio_apk"
    elif has_audio:
        primary_type = "audio"
    elif has_apk:
        primary_type = "apk"
    elif has_image:
        primary_type = "text_image"

    selected_agents = ["manager", "scam_detector", "golden_hour"]
    skipped_agents = []
    
    if has_audio:
        selected_agents.insert(2, "audio_analyzer")
    else:
        skipped_agents.append(("audio_analyzer", "no audio file uploaded"))
        
    if has_apk:
        selected_agents.insert(2, "apk_analyzer")
    else:
        skipped_agents.append(("apk_analyzer", "no file uploaded"))

    if has_url:
        selected_agents.insert(2, "osint")
    else:
        skipped_agents.append(("osint", "no URL found in input"))

    deduped = []
    for agent in selected_agents:
        norm = _normalize_agent(agent)
        if norm not in deduped:
            deduped.append(norm)
    return primary_type, deduped, skipped_agents


def _decode_b64(data: str) -> bytes:
    clean = (data or "").strip()
    if not clean:
        return b""
    if "," in clean and ";base64" in clean.split(",", 1)[0]:
        clean = clean.split(",", 1)[1]
    padding = len(clean) % 4
    if padding:
        clean += "=" * (4 - padding)
    return base64.b64decode(clean)


def _select_best_file(files: list[dict]) -> Optional[dict]:
    if not files:
        return None

    def score(item: dict) -> int:
        fn = str(item.get("file_name") or "").lower()
        ft = str(item.get("file_type") or "")
        if fn.endswith(".apk") or ft == "application/vnd.android.package-archive":
            return 100
        if ft.startswith("audio/") or fn.endswith((".mp3", ".wav", ".m4a", ".ogg")):
            return 90
        if ft.startswith("image/"):
            return 80
        return 10

    return sorted(files, key=score, reverse=True)[0]


def _truncate_text(value: Any, max_len: int = 500) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def _normalize_preprocessed_context(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(key, str):
            normalized[key] = value
    return normalized


def _extract_text_indicators(text: str) -> dict[str, Any]:
    body = str(text or "")
    url_matches = re.findall(r"https?://[^\s'\"]+", body, flags=re.IGNORECASE)
    phone_matches = re.findall(r"\b(?:\+?91[-\s]?)?[6-9]\d{9}\b", body)
    upi_matches = re.findall(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b", body)
    return {
        "url_count": len(url_matches),
        "phone_count": len(phone_matches),
        "upi_count": len(upi_matches),
        "urls": url_matches[:6],
        "phones": phone_matches[:6],
        "upi_ids": upi_matches[:6],
    }


async def _build_preprocessed_context(user_input: dict[str, Any]) -> dict[str, Any]:
    text = str(user_input.get("text") or "").strip()
    files = user_input.get("files") or []
    selected = _select_best_file(files)

    context: dict[str, Any] = {
        "source": "satark_preprocessor",
        "status": "ready",
        "text_excerpt": _truncate_text(text, 600),
        "text_hints": _extract_text_indicators(text),
        "file_hints": {},
        "notes": [],
    }

    if not selected:
        return context

    file_name = str(selected.get("file_name") or "evidence.bin")
    file_type = str(selected.get("file_type") or mimetypes.guess_type(file_name)[0] or "application/octet-stream")
    content_b64 = selected.get("content_base64")

    context["file_hints"] = {
        "filename": file_name,
        "mime_type": file_type,
    }

    if not content_b64:
        context["notes"].append("File content unavailable; used metadata-only preprocessing.")
        return context

    raw = _decode_b64(str(content_b64))
    if not raw:
        context["notes"].append("Uploaded file was empty after decoding.")
        return context

    try:
        if file_name.lower().endswith(".apk") or file_type == "application/vnd.android.package-archive":
            from agents.apk_analyzer.agent import run_static_analysis

            static_results = await asyncio.to_thread(run_static_analysis, raw, file_name)
            context["file_hints"].update(
                {
                    "kind": "apk",
                    "apk_static": {
                        "apk_hash": static_results.get("apk_hash"),
                        "c2_servers": _as_string_list(static_results.get("c2_servers")),
                        "hardcoded_urls": _as_string_list(static_results.get("hardcoded_urls"))[:10],
                        "hardcoded_ips": _as_string_list(static_results.get("hardcoded_ips"))[:10],
                        "suspicious_keywords": _as_string_list(static_results.get("strings_suspicious")),
                        "dangerous_permissions": _as_string_list(static_results.get("dangerous_permissions")),
                    },
                }
            )
            return context

        if file_type.startswith("audio/") or file_name.lower().endswith((".mp3", ".wav", ".m4a", ".ogg")):
            from agents.audio_analyzer.agent import analyze_audio_file

            audio_result = await asyncio.to_thread(analyze_audio_file, raw, file_type)
            entities = audio_result.get("extracted_entities") if isinstance(audio_result.get("extracted_entities"), dict) else {}
            context["file_hints"].update(
                {
                    "kind": "audio",
                    "audio_summary": _truncate_text(audio_result.get("call_summary") or audio_result.get("victim_advice") or "", 400),
                    "risk_level": str(audio_result.get("risk_level") or "").upper(),
                    "confidence": audio_result.get("confidence"),
                    "vishing_type": audio_result.get("vishing_type"),
                    "language_detected": audio_result.get("language_detected"),
                    "entities": {
                        "phones": _as_string_list(entities.get("phone_numbers") or entities.get("phones")),
                        "amounts": _as_string_list(entities.get("amounts")),
                    },
                }
            )
            return context

        from agents.scam_detector.agent import analyze_image

        image_result = await asyncio.to_thread(analyze_image, raw, file_type)
        entities = image_result.get("extracted_entities") if isinstance(image_result.get("extracted_entities"), dict) else {}
        context["file_hints"].update(
            {
                "kind": "image",
                "image_summary": _truncate_text(image_result.get("summary") or image_result.get("victim_advice") or "", 400),
                "risk_level": str(image_result.get("risk_level") or "").upper(),
                "confidence": image_result.get("confidence"),
                "scam_type": image_result.get("scam_type"),
                "signals_found": _as_string_list(image_result.get("signals_found")),
                "entities": {
                    "urls": _as_string_list(entities.get("urls")),
                    "phones": _as_string_list(entities.get("phone_numbers") or entities.get("phones")),
                    "amounts": _as_string_list(entities.get("amounts")),
                    "bank_names": _as_string_list(entities.get("bank_names")),
                },
            }
        )
    except Exception as exc:
        context["status"] = "partial"
        context["notes"].append(f"Preprocessing failed: {exc}")

    return context


def _build_similarity_context(similar: list[dict]) -> str:
    if not similar:
        return ""
    lines = []
    for item in similar[:3]:
        scam_type = str(item.get("scam_type") or "UNKNOWN")
        score = int(item.get("score") or 0)
        sub_type = str(item.get("sub_type") or "")
        if sub_type:
            lines.append(f"- {scam_type}/{sub_type} ({score}% match)")
        else:
            lines.append(f"- {scam_type} ({score}% match)")
    return "Similar known patterns:\n" + "\n".join(lines)


def _build_pipeline_call(
    user_input: dict,
    similar: Optional[list[dict]] = None,
    *,
    session_id: str | None = None,
    options: dict | None = None,
    user_context: dict | None = None,
    fraud_amount: float = 0,
    minutes_since_fraud: int | None = None,
) -> tuple[str, dict]:
    text = str(user_input.get("text") or "").strip()
    files = user_input.get("files") or []
    selected = _select_best_file(files)
    similarity_context = _build_similarity_context(similar or [])
    effective_text = text
    if similarity_context:
        effective_text = f"{text}\n\n{similarity_context}" if text else similarity_context

    payload = {
        "text": effective_text,
        "fraud_amount": max(0.0, float(fraud_amount or 0)),
        "minutes_since_fraud": minutes_since_fraud,
        "session_id": session_id,
        "options": options or {},
        "user_context": user_context or {},
        "recovery_answers": (options or {}).get("recovery_answers", {}),
        "preprocessed_context": _normalize_preprocessed_context((options or {}).get("preprocessed_context")),
    }

    if not selected:
        return "text", payload

    file_name = str(selected.get("file_name") or "evidence.bin")
    file_type = str(selected.get("file_type") or mimetypes.guess_type(file_name)[0] or "application/octet-stream")
    content_b64 = selected.get("content_base64")

    if not content_b64:
        # Metadata-only file (e.g. cloud URI). Keep analysis text-first while preserving flow classification.
        return "text", payload

    raw = _decode_b64(str(content_b64))

    if file_name.lower().endswith(".apk") or file_type == "application/vnd.android.package-archive":
        from agents.apk_analyzer.agent import run_static_analysis

        static_results = run_static_analysis(raw, file_name)
        return "apk", {
            "filename": file_name,
            "static_results": static_results,
            "text": effective_text,
            "fraud_amount": max(0.0, float(fraud_amount or 0)),
            "minutes_since_fraud": minutes_since_fraud,
            "session_id": session_id,
            "options": options or {},
            "user_context": user_context or {},
            "recovery_answers": (options or {}).get("recovery_answers", {}),
            "preprocessed_context": _normalize_preprocessed_context((options or {}).get("preprocessed_context")),
        }

    if file_type.startswith("audio/") or file_name.lower().endswith((".mp3", ".wav", ".m4a", ".ogg")):
        return "audio", {
            "audio_b64": base64.b64encode(raw).decode("utf-8"),
            "filename": file_name,
            "mime_type": file_type,
            "text": effective_text,
            "fraud_amount": max(0.0, float(fraud_amount or 0)),
            "minutes_since_fraud": minutes_since_fraud,
            "session_id": session_id,
            "options": options or {},
            "user_context": user_context or {},
            "recovery_answers": (options or {}).get("recovery_answers", {}),
            "preprocessed_context": _normalize_preprocessed_context((options or {}).get("preprocessed_context")),
        }

    return "image", {
        "image_b64": base64.b64encode(raw).decode("utf-8"),
        "filename": file_name,
        "mime_type": file_type,
        "text": effective_text,
        "fraud_amount": max(0.0, float(fraud_amount or 0)),
        "minutes_since_fraud": minutes_since_fraud,
        "session_id": session_id,
        "options": options or {},
        "user_context": user_context or {},
        "recovery_answers": (options or {}).get("recovery_answers", {}),
        "preprocessed_context": _normalize_preprocessed_context((options or {}).get("preprocessed_context")),
    }


def _looks_like_educational_apk(pipeline_result: dict, files: list[dict]) -> bool:
    if bool(
        pipeline_result.get("is_malicious")
        or pipeline_result.get("apk_is_malicious")
        or pipeline_result.get("apk_malicious")
    ):
        return False

    text_parts: list[str] = [
        str(pipeline_result.get("summary") or ""),
        str(pipeline_result.get("victim_advice") or ""),
        str(pipeline_result.get("malware_type") or ""),
        str(pipeline_result.get("plain_english_summary") or ""),
    ]
    for file_item in files:
        if isinstance(file_item, dict):
            text_parts.append(str(file_item.get("file_name") or ""))

    combined = " ".join(text_parts).lower()
    positive_markers = (
        "insecurebank",
        "training",
        "educational",
        "test apk",
        "vulnerable",
        "ctf",
        "lab",
        "demo app",
        "practice",
    )
    negative_markers = (
        "otp stealer",
        "credential harvester",
        "banking trojan",
        "active campaign",
        "live scam",
    )
    if any(marker in combined for marker in negative_markers):
        return False
    return any(marker in combined for marker in positive_markers)


def _bucket_to_minutes(time_bucket: str | None) -> int | None:
    key = str(time_bucket or "").strip().lower()
    if key == "minutes":
        return 15
    if key == "hours":
        return 180
    if key == "days":
        return 1440
    return None


def _build_legacy_input(user_input: dict) -> dict:
    text = str(user_input.get("text") or "").strip()
    files = user_input.get("files") or []
    selected = _select_best_file(files)
    if not selected:
        return {"type": "text", "text": text}

    file_name = str(selected.get("file_name") or "evidence.bin")
    file_type = str(selected.get("file_type") or mimetypes.guess_type(file_name)[0] or "application/octet-stream")
    content_b64 = selected.get("content_base64")
    if not content_b64:
        return {"type": "text", "text": text}

    raw = _decode_b64(str(content_b64))
    if file_name.lower().endswith(".apk") or file_type == "application/vnd.android.package-archive":
        return {"type": "apk", "bytes": raw, "filename": file_name}
    if file_type.startswith("audio/") or file_name.lower().endswith((".mp3", ".wav", ".m4a", ".ogg")):
        return {"type": "audio", "bytes": raw, "mime_type": file_type, "text": text}
    if file_type.startswith("image/"):
        return {"type": "image", "bytes": raw, "mime_type": file_type, "text": text}
    return {"type": "text", "text": text}


def _needs_legacy_fallback(pipeline_result: dict) -> bool:
    stages = pipeline_result.get("pipeline_stages") or []
    if isinstance(stages, list) and any(str(s).endswith("detection_failed") for s in stages):
        return True
    err_text = str(pipeline_result.get("error") or "").lower()
    if "resource_exhausted" in err_text or "quota exceeded" in err_text:
        return True
    return False


def _event_line(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {json.dumps(data, ensure_ascii=True)}\n\n"


async def _emit_event(run_id: str, event_name: str, payload: dict) -> None:
    run = RUN_STORE.get(run_id)
    if not run:
        return

    merged = {"run_id": run_id, "timestamp": _utc_now(), **payload}
    event = {"event": event_name, "data": merged}
    run.setdefault("events", []).append(event)
    for q in list(run.get("subscribers", [])):
        await q.put(event)


async def _finish_streams(run_id: str) -> None:
    run = RUN_STORE.get(run_id)
    if not run:
        return
    for q in list(run.get("subscribers", [])):
        await q.put(None)


def _extract_domains(urls: list[str]) -> list[str]:
    domains = []
    for u in urls:
        candidate = str(u or "").strip()
        if not candidate:
            continue
        parsed = urlparse(candidate)
        domain = parsed.netloc or parsed.path.split("/")[0]
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _is_generic_verdict_text(value: str) -> bool:
    normalized = " ".join(str(value or "").strip().split()).casefold()
    return normalized in {
        "",
        "analysis complete",
        "analysis completed",
        "review complete",
        "review completed",
    }


def _is_reporting_oriented_text(value: str) -> bool:
    text = str(value or "")
    if not text.strip():
        return False
    return bool(
        re.search(
            r"\b(report|complaint|complain|helpline|1930|cyber\s*crime|ncrp|fir|police|chakshu|portal)\b",
            text,
            re.IGNORECASE,
        )
    )


def _default_preventive_actions() -> list[str]:
    return [
        "Do not click the link or reply to the message.",
        "Block the sender and mark the SMS as spam in your messaging app.",
        "Keep a screenshot for your records, then delete the message.",
        "Monitor your bank and wallet apps for unusual activity for the next 24 hours.",
    ]


def _sanitize_actions_for_no_reporting(actions: list[str]) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for action in actions:
        item = " ".join(str(action or "").strip().split())
        if not item:
            continue
        if _is_reporting_oriented_text(item):
            continue
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(item)

    if len(cleaned) < 3:
        for fallback in _default_preventive_actions():
            key = fallback.casefold()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(fallback)
            if len(cleaned) >= 4:
                break
    return cleaned[:6]


def _infer_exposure_from_text(text: str) -> dict[str, bool]:
    source = str(text or "").strip().lower()
    if not source:
        return {
            "money_lost": False,
            "shared_sensitive": False,
            "clicked_link": False,
        }

    money_lost = bool(
        re.search(
            r"\b(lost|loss|debited|transferred|sent|paid|payment\s+failed\s+after\s+debit|money\s+gone|amount\s+gone|scammed\s+for|upi\s+transfer|wire\s+transfer)\b",
            source,
            re.IGNORECASE,
        )
    )
    shared_sensitive = bool(
        re.search(
            r"\b(shared|gave|provided|told)\b.{0,40}\b(otp|pin|password|cvv|card\s+number|bank\s+detail|net\s+banking|login\s+detail|credential)\b",
            source,
            re.IGNORECASE,
        )
    )
    clicked_link = bool(
        re.search(
            r"\b(clicked|opened|visited|tap(?:ped)?)\b.{0,30}\b(link|url|website|site)\b",
            source,
            re.IGNORECASE,
        )
    )

    return {
        "money_lost": money_lost,
        "shared_sensitive": shared_sensitive,
        "clicked_link": clicked_link,
    }


def _extract_stage(pipeline_result: dict, stage_name: str) -> dict:
    stages = pipeline_result.get("pipeline_stages")
    if isinstance(stages, dict):
        stage = stages.get(stage_name)
        if isinstance(stage, dict):
            return stage
    return {}


def _normalize_recommended_actions(pipeline_result: dict) -> list[str]:
    actions: list[str] = []

    priority_actions = pipeline_result.get("priority_actions")
    if isinstance(priority_actions, list):
        for item in priority_actions:
            if isinstance(item, dict):
                action = str(item.get("action") or "").strip()
                if action:
                    actions.append(action)
            elif str(item).strip():
                actions.append(str(item).strip())

    victim_advice = str(pipeline_result.get("victim_advice") or "").strip()
    if victim_advice:
        actions.append(victim_advice)

    deduped: list[str] = []
    seen: set[str] = set()
    for action in actions:
        cleaned = " ".join(str(action).strip().split())
        if not cleaned:
            continue
        key = cleaned.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cleaned)

    if deduped:
        return deduped[:6]

    return [
        "Do not click suspicious links",
        "Do not share OTP or PIN",
        "Block or report the sender on the platform",
        "Preserve evidence and monitor for account impact",
    ]


def _build_ncrp_complaint_body(
    *,
    case_id: str,
    scam_type: str,
    risk_level: str,
    summary: str,
    entities: dict,
    osint_payload: Optional[dict],
    evidence: list[str],
) -> str:
    urls = _as_string_list(entities.get("urls"))
    phones = _as_string_list(entities.get("phones") or entities.get("phone_numbers"))
    upi_ids = _as_string_list(entities.get("upi_ids"))
    account_numbers = _as_string_list(entities.get("account_numbers"))

    osint_summary = ""
    osint_red_flags: list[str] = []
    if isinstance(osint_payload, dict):
        osint_summary = str(
            osint_payload.get("threat_summary")
            or osint_payload.get("osint_summary")
            or ""
        ).strip()
        raw_flags = osint_payload.get("red_flags")
        if isinstance(raw_flags, list):
            osint_red_flags = [str(x).strip() for x in raw_flags if str(x).strip()]

    def _bullet(items: list[str]) -> str:
        return "\n".join([f"- {x}" for x in items]) if items else "- (not available)"

    return (
        "CYBER CRIME COMPLAINT (NCRP DRAFT)\n"
        f"Acknowledgment/Case ID: {case_id}\n"
        "\n"
        "1) Complainant Details\n"
        "Name: [Your Name]\n"
        "Mobile: [Your Mobile Number]\n"
        "Email: [Your Email]\n"
        "Address: [Your Address]\n"
        "\n"
        "2) Incident Details\n"
        "Category/Type: "
        f"{scam_type}\n"
        f"Risk Level: {risk_level}\n"
        "Date & Time of Incident: [DD/MM/YYYY, HH:MM]\n"
        "Mode: Online (phishing/impersonation/UPI/etc.)\n"
        "Description of Incident:\n"
        f"{summary.strip() or '[Describe what happened in your own words]'}\n"
        "\n"
        "3) Suspect / Accused Details (as available)\n"
        "Phone Numbers:\n"
        f"{_bullet(phones)}\n"
        "UPI IDs:\n"
        f"{_bullet(upi_ids)}\n"
        "Bank Account Numbers:\n"
        f"{_bullet(account_numbers)}\n"
        "Suspicious URLs / Links:\n"
        f"{_bullet(urls)}\n"
        "\n"
        "4) OSINT Findings (automated)\n"
        f"{osint_summary or 'OSINT scan completed. Detailed indicators are available in the report.'}\n"
        + ("\nRed Flags:\n" + _bullet(osint_red_flags) + "\n" if osint_red_flags else "")
        + "\n"
        "5) Evidence Preserved / Attached\n"
        f"{_bullet(evidence)}\n"
        "\n"
        "6) Request\n"
        "I request the Cyber Crime Cell to register my complaint, investigate the above incident, and initiate fund-protection / recovery steps at the earliest.\n"
        "\n"
        "7) Declaration\n"
        "I declare that the information provided above is true to the best of my knowledge.\n"
        "\n"
        "Place: [City]\n"
        "Date: [DD/MM/YYYY]\n"
        "Signature: [Your Name]\n"
    )


def _load_persisted_case(run_id: str) -> Optional[dict]:
    db = get_db()
    if not db:
        return None
    try:
        doc = db.collection("cases").document(run_id).get()
        if not doc.exists:
            return None
        payload = doc.to_dict() or {}
        risk_level = str(payload.get("risk_level") or "UNKNOWN")
        confidence = int(payload.get("confidence") or 0)
        summary = str(payload.get("summary") or "Recovered case result")
        try:
            similar_cases = int(payload.get("similar_cases_found") or payload.get("similar_cases") or 0)
        except Exception:
            similar_cases = 0
        signals_found = payload.get("signals_found")
        if not isinstance(signals_found, list):
            signals_found = payload.get("red_flags")
        if not isinstance(signals_found, list):
            signals_found = []
        reporting_raw = payload.get("reporting_recommendation") if isinstance(payload.get("reporting_recommendation"), dict) else {}
        reporting_reason = str(reporting_raw.get("reason") or "").strip()
        persisted_requires_reporting = bool(
            payload.get("requires_reporting", False)
            or reporting_raw.get("should_report_now", False)
        )
        if persisted_requires_reporting and not reporting_reason:
            reporting_reason = "Reporting was marked as required for this case."
        if not persisted_requires_reporting and not reporting_reason:
            reporting_reason = "No immediate reporting guidance was returned for this case."
        reporting_recommendation = {
            "should_report_now": bool(reporting_raw.get("should_report_now", False) or persisted_requires_reporting),
            "reason": reporting_reason,
        }
        recommended = _as_string_list(payload.get("recommended_actions"))
        if not recommended:
            recommended = _normalize_recommended_actions(payload)
        persisted_verdict = str(payload.get("verdict") or "").strip()
        if _is_generic_verdict_text(persisted_verdict):
            persisted_verdict = "Analysis complete"
        presentation_payload = payload.get("presentation") if isinstance(payload.get("presentation"), dict) else {}
        debug_payload = payload.get("debug") if isinstance(payload.get("debug"), dict) else {}
        presentation = {
            "headline": str(presentation_payload.get("headline") or persisted_verdict).strip() or persisted_verdict,
            "summary_paragraph": str(presentation_payload.get("summary_paragraph") or summary).strip() or summary,
            "evidence_bullets": _as_string_list(presentation_payload.get("evidence_bullets") or signals_found)[:6],
            "actions": _as_string_list(presentation_payload.get("actions") or recommended)[:4],
            "reporting_note": reporting_reason,
        }
        debug = {
            "risk_level": str(debug_payload.get("risk_level") or risk_level),
            "confidence": int(debug_payload.get("confidence") or confidence),
            "similar_cases": int(debug_payload.get("similar_cases") or similar_cases),
            "patterns": debug_payload.get("patterns") if isinstance(debug_payload.get("patterns"), list) else [],
        }
        return {
            "run_id": run_id,
            "case_id": run_id,
            "status": "completed",
            "input_type": payload.get("input_type", "text"),
            "verdict": persisted_verdict,
            "summary": summary,
            "conversational_reply": summary,
            "scam_type": payload.get("scam_type", "UNKNOWN"),
            "official_category": payload.get("category") or payload.get("scam_type", "UNKNOWN"),
            "category": payload.get("category") or payload.get("scam_type", "UNKNOWN"),
            "risk_level": risk_level,
            "confidence": confidence,
            "response_mode": str(payload.get("response_mode") or "proactive_warning"),
            "requires_reporting": persisted_requires_reporting,
            "requires_emergency": bool(payload.get("requires_emergency", False)),
            "requires_financial_blocking": bool(payload.get("requires_financial_blocking", payload.get("requires_account_block", False))),
            "requires_account_block": bool(payload.get("requires_financial_blocking", payload.get("requires_account_block", False))),
            "reporting_recommendation": reporting_recommendation,
            "presentation_sections": payload.get("presentation_sections") if isinstance(payload.get("presentation_sections"), dict) else {
                "headline": persisted_verdict,
                "status_line": str(summary or "Recovered persisted result."),
                "primary_actions_title": "What to do now",
                "actions_title": "What to do now",
                "evidence_title": "Why this decision was made",
            },
            "response_sections": {
                "overview": summary,
                "why_flagged": _as_string_list(signals_found)[:4],
                "next_steps": recommended,
                "reporting_guidance": reporting_reason,
            },
            "presentation": presentation,
            "debug": debug,
            "presentation_markdown": str(payload.get("presentation_markdown") or "").strip() or (
                "## What this looks like\n"
                f"{presentation['summary_paragraph']}\n\n"
                "## Why I'm saying that\n"
                + "\n".join([f"- {x}" for x in presentation["evidence_bullets"]])
                + "\n\n## What to do now\n"
                + "\n".join([f"{idx + 1}. {x}" for idx, x in enumerate(presentation["actions"])])
                + "\n\n## Reporting\n"
                + f"{presentation['reporting_note']}"
            ),
            "signals_found": _as_string_list(signals_found),
            "similar_cases": similar_cases,
            "golden_hour_active": bool(payload.get("golden_hour_active", False)),
            "golden_hour_status": "ACTIVE" if payload.get("golden_hour_active") else "STANDBY",
            "golden_hour_message": "Recovered persisted result.",
            "entities": {
                "phone_numbers": [],
                "domains": [],
                "urls": [],
                "ips": [],
                "banks_claimed": [],
            },
            "osint": None,
            "audio_analysis": None,
            "apk_analysis": None,
            "evidence_summary": _as_string_list(signals_found)[:5],
            "recommended_actions": recommended,
            "complaint_draft": payload.get("complaint_draft") if isinstance(payload.get("complaint_draft"), dict) else None,
            "follow_up_actions": {
                "calendar_event_created": False,
                "calendar_deep_link": None,
                "calendar_url": None,
                "task_created": False,
                "task_deep_link": None,
                "task_url": None,
                "doc_created": False,
                "doc_url": None,
                "gmail_draft_created": False,
                "gmail_draft_url": None,
                "tgcsb_alert_sent": False,
            },
            "calendar_deep_link": None,
            "task_deep_link": None,
            "gmail_draft_url": None,
            "agent_results": {
                "manager": {"status": "done"},
                "scam_detector": {"status": "done"},
                "audio_analyzer": {"status": "skipped"},
                "apk_analyzer": {"status": "skipped"},
                "osint": {"status": "done"},
                "golden_hour": {"status": "done"},
            },
            "timestamps": {
                "created_at": payload.get("timestamp"),
                "completed_at": payload.get("timestamp"),
            },
            "raw": payload,
        }
    except Exception:
        return None


def _build_result_document(run_ctx: dict, pipeline_result: dict, primary_type: str, selected_agents: list[str]) -> dict:
    scam_type = str(pipeline_result.get("scam_type") or "UNKNOWN")
    raw_risk_level = str(pipeline_result.get("risk_level") or "UNKNOWN").upper()

    confidence_raw = pipeline_result.get("confidence")
    try:
        confidence_float = float(confidence_raw or 0)
    except Exception:
        confidence_float = 0.0
    if 0 < confidence_float <= 1:
        confidence_float *= 100
    confidence = int(round(confidence_float))
    confidence = max(0, min(confidence, 100))

    allowed_risks = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    risk_level = raw_risk_level if raw_risk_level in allowed_risks else "UNKNOWN"

    apk_malicious = bool(
        pipeline_result.get("is_malicious")
        or pipeline_result.get("apk_is_malicious")
        or pipeline_result.get("apk_malicious")
    )

    extracted = pipeline_result.get("extracted_entities") if isinstance(pipeline_result.get("extracted_entities"), dict) else {}
    urls = _as_string_list(extracted.get("urls"))
    phones = _as_string_list(extracted.get("phone_numbers") or extracted.get("phones"))
    ips = _as_string_list(extracted.get("ips"))
    banks_claimed = _as_string_list(extracted.get("bank_names") or extracted.get("banks_claimed"))

    osint_stage = _extract_stage(pipeline_result, "osint")
    if not osint_stage and isinstance(pipeline_result.get("osint"), dict):
        osint_stage = pipeline_result.get("osint")  # type: ignore[assignment]
    osint_payload: Optional[dict] = None
    if "osint" in selected_agents:
        threat_summary = str(
            osint_stage.get("threat_summary")
            or pipeline_result.get("osint_summary")
            or ""
        ).strip()
        if threat_summary and (
            threat_summary.casefold().startswith("not run")
            or threat_summary.casefold().startswith("skipped")
        ):
            threat_summary = ""

        domains_map = osint_stage.get("domains") if isinstance(osint_stage.get("domains"), dict) else {}
        ips_map = osint_stage.get("ips") if isinstance(osint_stage.get("ips"), dict) else {}
        urls_map = osint_stage.get("urls") if isinstance(osint_stage.get("urls"), dict) else {}
        red_flags_list = osint_stage.get("red_flags") if isinstance(osint_stage.get("red_flags"), list) else []

        has_any_osint = bool(threat_summary) or bool(domains_map) or bool(ips_map) or bool(urls_map) or bool(red_flags_list)
        if has_any_osint:
            osint_payload = {
                "threat_summary": threat_summary,
                "overall_threat_score": int(
                    osint_stage.get("overall_threat_score")
                    or osint_stage.get("threat_score")
                    or pipeline_result.get("threat_score")
                    or 0
                ),
                "domains": domains_map,
                "ips": ips_map,
                "urls": urls_map,
                "red_flags": red_flags_list,
            }

    raw_action_steps = pipeline_result.get("action_steps")
    if not isinstance(raw_action_steps, list):
        raw_action_steps = pipeline_result.get("recommended_actions")
    recommended_actions = _as_string_list(raw_action_steps) if isinstance(raw_action_steps, list) else []
    if not recommended_actions:
        recommended_actions = _normalize_recommended_actions(pipeline_result)

    verdict = str(pipeline_result.get("verdict") or "").strip()
    if not verdict:
        verdict = "Analysis complete"

    summary_text = str(pipeline_result.get("summary") or pipeline_result.get("victim_advice") or "").strip()
    if not summary_text:
        summary_text = "Analysis completed. Review the evidence and action steps."

    files = run_ctx["request"]["user_input"].get("files") or []

    response_mode = str(pipeline_result.get("response_mode") or "").strip().lower() or "proactive_warning"
    category = str(
        pipeline_result.get("category")
        or pipeline_result.get("official_category")
        or pipeline_result.get("scam_type")
        or scam_type
    ).strip() or scam_type
    requires_reporting = bool(pipeline_result.get("requires_reporting", False))
    requires_emergency = bool(pipeline_result.get("requires_emergency", False))
    requires_financial_blocking = bool(
        pipeline_result.get("requires_financial_blocking", pipeline_result.get("requires_account_block", False))
    )
    requires_mcp = bool(pipeline_result.get("requires_mcp", False))
    mcp_plan = pipeline_result.get("mcp_plan") if isinstance(pipeline_result.get("mcp_plan"), dict) else {}

    reporting_recommendation_raw = (
        pipeline_result.get("reporting_recommendation")
        if isinstance(pipeline_result.get("reporting_recommendation"), dict)
        else {}
    )
    request_payload = run_ctx.get("request") if isinstance(run_ctx.get("request"), dict) else {}
    request_options = request_payload.get("options") if isinstance(request_payload.get("options"), dict) else {}
    recovery_answers = request_options.get("recovery_answers") if isinstance(request_options.get("recovery_answers"), dict) else {}
    request_user_input = request_payload.get("user_input") if isinstance(request_payload.get("user_input"), dict) else {}
    text_exposure = _infer_exposure_from_text(str(request_user_input.get("text") or ""))
    reported_money_loss = bool(recovery_answers.get("did_lose_money_or_share_bank_details"))
    try:
        reported_money_loss = reported_money_loss or float(request_options.get("fraud_amount") or 0) > 0
    except Exception:
        pass
    reported_sensitive_share = bool(
        recovery_answers.get("shared_sensitive_data")
        or recovery_answers.get("shared_otp_or_pin")
        or recovery_answers.get("shared_bank_details")
    )
    reported_clicked_link = bool(recovery_answers.get("clicked_link"))

    reporting_reason = str(reporting_recommendation_raw.get("reason") or "").strip()
    inferred_compromise = bool(
        reported_money_loss
        or reported_sensitive_share
        or reported_clicked_link
        or text_exposure.get("money_lost")
        or text_exposure.get("shared_sensitive")
    )
    if not reporting_reason and inferred_compromise:
        reasons: list[str] = []
        if reported_money_loss or text_exposure.get("money_lost"):
            reasons.append("possible money loss")
        if reported_sensitive_share or text_exposure.get("shared_sensitive"):
            reasons.append("possible sharing of OTP/PIN or banking credentials")
        if reported_clicked_link or text_exposure.get("clicked_link"):
            reasons.append("possible malicious link interaction")
        requires_reporting = True
        requires_emergency = requires_emergency or bool(reported_money_loss or text_exposure.get("money_lost"))
        requires_financial_blocking = requires_financial_blocking or bool(
            reported_money_loss
            or reported_sensitive_share
            or text_exposure.get("money_lost")
            or text_exposure.get("shared_sensitive")
        )
        reporting_reason = "Potential compromise detected (" + ", ".join(reasons[:3]) + "). Report now and begin immediate protective actions."

    if not reporting_reason:
        requires_reporting = False
    no_reporting_mode = not requires_reporting and not reporting_reason
    if no_reporting_mode:
        reporting_reason = (
            "No money loss, no link click, and no sensitive data sharing were detected from your answers, "
            "so immediate reporting is not required."
        )
        requires_emergency = False
        requires_financial_blocking = False
    reporting_recommendation = {
        "should_report_now": bool((reporting_recommendation_raw.get("should_report_now", False) or requires_reporting) and requires_reporting and bool(reporting_reason)),
        "reason": reporting_reason,
    }

    if no_reporting_mode:
        recommended_actions = _sanitize_actions_for_no_reporting(recommended_actions)
        if _is_generic_verdict_text(verdict):
            verdict = "Likely scam attempt with no confirmed compromise from your answers."
        summary_text = (
            "This looks like a scam lure, but your answers do not indicate direct compromise yet. "
            "Follow preventive safety steps."
        )

    presentation_sections_raw = (
        pipeline_result.get("presentation_sections")
        if isinstance(pipeline_result.get("presentation_sections"), dict)
        else {}
    )
    actions_title = str(
        presentation_sections_raw.get("actions_title")
        or presentation_sections_raw.get("primary_actions_title")
        or "What to do now"
    ).strip() or "What to do now"
    status_line_default = str(summary_text or "Review the manager response and follow the recommended actions.").strip()
    presentation_sections = {
        "headline": str(presentation_sections_raw.get("headline") or verdict).strip() or verdict,
        "status_line": str(presentation_sections_raw.get("status_line") or status_line_default).strip() or status_line_default,
        "primary_actions_title": actions_title,
        "actions_title": actions_title,
        "evidence_title": str(presentation_sections_raw.get("evidence_title") or "Why this decision was made").strip() or "Why this decision was made",
    }

    why_this_decision = _as_string_list(pipeline_result.get("why_this_decision"))

    conversational_reply = str(pipeline_result.get("conversational_reply") or "").strip()
    if not conversational_reply:
        conversational_reply = summary_text
    if no_reporting_mode:
        conversational_reply = summary_text

    evidence_rows: list[dict[str, Any]] = []
    raw_evidence = pipeline_result.get("evidence")
    if isinstance(raw_evidence, list):
        for item in raw_evidence[:20]:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label") or "").strip()
            if not label:
                continue
            confidence_val = item.get("confidence")
            weight_val = item.get("weight")
            try:
                confidence_num = float(confidence_val) if confidence_val is not None else None
            except Exception:
                confidence_num = None
            try:
                weight_num = int(round(float(weight_val))) if weight_val is not None else None
            except Exception:
                weight_num = None
            evidence_rows.append(
                {
                    "label": label,
                    "confidence": confidence_num,
                    "weight": weight_num,
                }
            )

    evidence_summary = _as_string_list(pipeline_result.get("signals_found") or pipeline_result.get("red_flags"))
    if not evidence_summary:
        evidence_summary = [
            "Automated multi-agent analysis completed",
            "Pattern checks and response planning executed",
        ]
    if not why_this_decision:
        why_this_decision = [str(row.get("label") or "").strip() for row in evidence_rows if str(row.get("label") or "").strip()][:6]
    if not why_this_decision:
        why_this_decision = evidence_summary[:6]

    presentation_raw = pipeline_result.get("presentation") if isinstance(pipeline_result.get("presentation"), dict) else {}
    presentation_actions = _as_string_list(presentation_raw.get("actions") or recommended_actions)
    if not presentation_actions:
        presentation_actions = recommended_actions
    presentation_actions = presentation_actions[:4]
    if len(presentation_actions) < 4:
        for item in recommended_actions:
            text = str(item or "").strip()
            if not text:
                continue
            if text.casefold() in {x.casefold() for x in presentation_actions}:
                continue
            presentation_actions.append(text)
            if len(presentation_actions) >= 4:
                break
    recommended_actions = presentation_actions[:4]

    presentation_evidence = _as_string_list(presentation_raw.get("evidence_bullets") or why_this_decision)[:6]
    if not presentation_evidence:
        presentation_evidence = why_this_decision[:6]

    presentation = {
        "headline": str(presentation_raw.get("headline") or verdict).strip() or verdict,
        "summary_paragraph": str(presentation_raw.get("summary_paragraph") or summary_text).strip() or summary_text,
        "evidence_bullets": presentation_evidence,
        "actions": recommended_actions,
        "reporting_note": str(presentation_raw.get("reporting_note") or reporting_reason).strip() or reporting_reason,
    }

    debug_raw = pipeline_result.get("debug") if isinstance(pipeline_result.get("debug"), dict) else {}
    debug = {
        "risk_level": str(debug_raw.get("risk_level") or risk_level),
        "confidence": float(debug_raw.get("confidence") if isinstance(debug_raw.get("confidence"), (int, float)) else confidence),
        "similar_cases": int(debug_raw.get("similar_cases") if isinstance(debug_raw.get("similar_cases"), (int, float)) else 0),
        "patterns": debug_raw.get("patterns") if isinstance(debug_raw.get("patterns"), list) else [],
    }

    presentation_markdown = str(pipeline_result.get("presentation_markdown") or "").strip()
    if not presentation_markdown:
        presentation_markdown = (
            "## What this looks like\n"
            f"{presentation['summary_paragraph']}\n\n"
            "## Why I'm saying that\n"
            + "\n".join([f"- {item}" for item in presentation["evidence_bullets"]])
            + "\n\n## What to do now\n"
            + "\n".join([f"{idx + 1}. {item}" for idx, item in enumerate(presentation["actions"])])
            + "\n\n## Reporting\n"
            + f"{presentation['reporting_note']}"
        )

    def _normalize_intel_type(value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return "Other"
        upper = raw.upper()
        mapping = {
            "KYC FRAUD": "KYC Fraud",
            "UPI FRAUD": "UPI Impersonation",
            "UPI": "UPI Impersonation",
            "PART-TIME JOB SCAM": "Job Scam",
            "JOB/EMPLOYMENT FRAUD": "Job Scam",
            "JOB SCAM": "Job Scam",
            "INVESTMENT FRAUD": "Investment Fraud",
            "LOTTERY/PRIZE FRAUD": "Other",
            "FAKE CUSTOMER CARE": "OTP Phishing",
            "CUSTOMER CARE FRAUD": "OTP Phishing",
            "DIGITAL ARREST": "OTP Phishing",
            "LOAN APP FRAUD": "Loan App Threat",
            "ELECTRICITY BILL": "Electricity Bill",
        }
        if upper in mapping:
            return mapping[upper]
        if "KYC" in upper:
            return "KYC Fraud"
        if "UPI" in upper:
            return "UPI Impersonation"
        if "JOB" in upper or "PART" in upper:
            return "Job Scam"
        if "INVEST" in upper or "TRAD" in upper:
            return "Investment Fraud"
        if "ELECTRIC" in upper or "TSECL" in upper:
            return "Electricity Bill"
        if "LOAN" in upper or "APP" in upper:
            return "Loan App Threat"
        if "OTP" in upper or "PHISH" in upper or "CUSTOMER" in upper or "DIGITAL ARREST" in upper:
            return "OTP Phishing"
        return "Other"

    intel_type = _normalize_intel_type(scam_type)
    demo_total = int(get_fraud_patterns_count(active_only=True, cache_ttl_seconds=600, source="demo_seed") or 0)
    if demo_total > 0:
        intel_corpus_size = demo_total
        intel_type_count = int(
            get_fraud_patterns_count_by_type(
                intel_type,
                active_only=True,
                cache_ttl_seconds=600,
                source="demo_seed",
            )
            or 0
        )
    else:
        intel_corpus_size = int(get_fraud_patterns_count(active_only=True, cache_ttl_seconds=600) or 0)
        intel_type_count = int(get_fraud_patterns_count_by_type(intel_type, active_only=True, cache_ttl_seconds=600) or 0)
    raw_pattern_matches = run_ctx.get("similar_patterns")
    pattern_matches: list[dict[str, Any]] = []
    if isinstance(raw_pattern_matches, list):
        for item in raw_pattern_matches[:5]:
            if not isinstance(item, dict):
                continue
            scam = str(item.get("scam_type") or "").strip() or None
            sub = str(item.get("sub_type") or "").strip() or None
            score = item.get("score")
            try:
                score_int = int(round(float(score or 0)))
            except Exception:
                score_int = 0
            pattern_matches.append(
                {
                    "scam_type": scam,
                    "sub_type": sub,
                    "score": max(0, min(score_int, 100)),
                }
            )

    # Similar case count should be retrieval-driven (vector matches), not corpus metadata.
    try:
        retrieved_count = int(run_ctx.get("similar_patterns_count") or 0)
    except Exception:
        retrieved_count = 0
    if retrieved_count <= 0:
        retrieved_count = len(pattern_matches)
    similar_cases = max(0, retrieved_count)
    if not isinstance(debug.get("patterns"), list) or not debug.get("patterns"):
        debug["patterns"] = pattern_matches
    debug["similar_cases"] = int(similar_cases)

    calendar_event = pipeline_result.get("calendar_event") if isinstance(pipeline_result.get("calendar_event"), dict) else {}
    tasks_payload = pipeline_result.get("google_tasks") if isinstance(pipeline_result.get("google_tasks"), dict) else {}
    doc_payload = pipeline_result.get("case_report_doc") if isinstance(pipeline_result.get("case_report_doc"), dict) else {}
    gmail_payload = pipeline_result.get("gmail_draft") if isinstance(pipeline_result.get("gmail_draft"), dict) else {}
    calendar_url = str(
        calendar_event.get("deep_link")
        or calendar_event.get("event_url")
        or calendar_event.get("html_link")
        or calendar_event.get("url")
        or ""
    ).strip()
    task_url = str(tasks_payload.get("task_url") or tasks_payload.get("deep_link") or tasks_payload.get("url") or "").strip()
    doc_url = str(doc_payload.get("doc_url") or doc_payload.get("deep_link") or doc_payload.get("url") or "").strip()
    gmail_url = str(gmail_payload.get("draft_url") or gmail_payload.get("deep_link") or gmail_payload.get("url") or "").strip()
    tasks_created = bool(tasks_payload.get("created")) or bool(task_url)
    doc_created = bool(doc_payload.get("created")) or bool(doc_url)
    gmail_created = bool(gmail_payload.get("created")) or bool(gmail_url)
    fir_template = pipeline_result.get("fir_template")
    if isinstance(fir_template, dict):
        complaint_body = str(fir_template.get("case_summary") or "")
    else:
        complaint_body = str(fir_template or "")

    # If the model didn't produce a real FIR/NCRP-ready body, generate a pre-filled NCRP-style draft.
    generated_complaint = _build_ncrp_complaint_body(
        case_id=str(run_ctx.get("case_id") or ""),
        scam_type=scam_type,
        risk_level=risk_level,
        summary=summary_text,
        entities=extracted if isinstance(extracted, dict) else {},
        osint_payload=osint_payload,
        evidence=evidence_summary,
    )
    if not complaint_body or len(complaint_body.strip()) < 200:
        complaint_body = generated_complaint

    complaint_payload: Optional[dict[str, Any]] = None
    if requires_reporting:
        complaint_payload = {
            "title": "Cyber Fraud Complaint Draft",
            "acknowledgment_id": run_ctx["case_id"],
            "body": complaint_body,
        }

    response_sections = {
        "overview": presentation["summary_paragraph"],
        "why_flagged": presentation["evidence_bullets"],
        "next_steps": presentation["actions"],
        "reporting_guidance": presentation["reporting_note"],
    }

    modality_audio = None
    if "audio_analyzer" in selected_agents:
        modality_audio = {
            "summary": str(pipeline_result.get("summary") or pipeline_result.get("victim_advice") or "Audio fraud analysis completed."),
            "confidence": confidence,
            "risk_level": risk_level,
        }

    modality_apk = None
    if "apk_analyzer" in selected_agents:
        modality_apk = {
            "summary": str(pipeline_result.get("summary") or "APK static and behavioral indicators analyzed."),
            "risk_level": risk_level,
            "is_malicious": bool(apk_malicious),
        }

    selected_set = set(selected_agents)
    agent_results = {
        "manager": {"status": "done"},
        "scam_detector": {"status": "done" if "scam_detector" in selected_set else "skipped"},
        "audio_analyzer": {"status": "done" if "audio_analyzer" in selected_set else "skipped"},
        "apk_analyzer": {"status": "done" if "apk_analyzer" in selected_set else "skipped"},
        "osint": {"status": "done" if "osint" in selected_set else "skipped"},
        "golden_hour": {"status": "done" if "golden_hour" in selected_set else "skipped"},
    }

    golden_hour_active = bool(pipeline_result.get("golden_hour_active"))
    calendar_created = bool(calendar_event.get("created", False))
    calendar_attempted = bool(calendar_event.get("attempted", False))
    calendar_event_id = str(calendar_event.get("event_id") or "").strip()
    calendar_start = str(calendar_event.get("start_time") or "").strip()
    calendar_error = str(calendar_event.get("error") or "").strip()

    if calendar_created:
        event_id_hint = f" (event_id: {calendar_event_id})" if calendar_event_id else ""
        golden_hour_message = f"Calendar reminder created{(' for ' + calendar_start) if calendar_start else ''}.{event_id_hint}"
    elif golden_hour_active and calendar_attempted and calendar_error:
        golden_hour_message = f"Golden Hour active; calendar reminder failed: {calendar_error}"
    elif golden_hour_active:
        golden_hour_message = "Golden Hour active. Follow the manager-provided action plan."
    else:
        golden_hour_message = "Follow the manager-provided action plan."

    return {
        "run_id": run_ctx["run_id"],
        "case_id": run_ctx["case_id"],
        "status": run_ctx["status"],
        "input_type": primary_type,
        "verdict": verdict,
        "summary": summary_text,
        "conversational_reply": conversational_reply,
        "scam_type": scam_type,
        "official_category": category,
        "category": category,
        "risk_level": risk_level,
        "confidence": confidence,
        "response_mode": response_mode,
        "requires_reporting": requires_reporting,
        "requires_emergency": requires_emergency,
        "requires_financial_blocking": requires_financial_blocking,
        "requires_account_block": requires_financial_blocking,
        "reporting_recommendation": reporting_recommendation,
        "requires_mcp": requires_mcp,
        "mcp_plan": mcp_plan,
        "why_this_decision": why_this_decision,
        "presentation_sections": presentation_sections,
        "response_sections": response_sections,
        "presentation": presentation,
        "debug": debug,
        "presentation_markdown": presentation_markdown,
        "signals_found": _as_string_list(pipeline_result.get("signals_found") or pipeline_result.get("red_flags")),
        "similar_cases": similar_cases,
        "intel_corpus_size": intel_corpus_size,
        "intel_type": intel_type,
        "intel_type_count": intel_type_count,
        "pattern_matches": pattern_matches,
        "golden_hour_active": bool(golden_hour_active),
        "golden_hour_status": "ACTIVE" if golden_hour_active else "STANDBY",
        "golden_hour_message": golden_hour_message,
        "entities": {
            "phone_numbers": phones,
            "domains": _extract_domains(urls),
            "urls": urls,
            "ips": ips,
            "banks_claimed": banks_claimed,
        },
        "osint": osint_payload,
        "audio_analysis": modality_audio,
        "apk_analysis": modality_apk,
        "evidence_summary": evidence_summary,
        "action_steps": recommended_actions,
        "recommended_actions": recommended_actions,
        "complaint_draft": complaint_payload,
        "follow_up_actions": {
            "calendar_event_created": bool(calendar_event.get("created", False)),
            "calendar_event_id": calendar_event_id or None,
            "calendar_start_time": calendar_start or None,
            "calendar_attempted": calendar_attempted,
            "calendar_error": calendar_error or None,
            "calendar_url": calendar_url or None,
            "calendar_deep_link": calendar_url or None,
            "task_created": tasks_created,
            "task_url": task_url or None,
            "task_deep_link": task_url or None,
            "doc_created": doc_created,
            "doc_url": doc_url or None,
            "doc_deep_link": doc_url or None,
            "gmail_draft_created": gmail_created,
            "gmail_draft_url": gmail_url or None,
            "tgcsb_alert_sent": False,
        },
        "calendar_deep_link": calendar_url or None,
        "task_deep_link": task_url or None,
        "gmail_draft_url": gmail_url or None,
        "agent_results": agent_results,
        "evidence": evidence_rows,
        "submitted_evidence": [
            {
                "type": f.get("file_type") or "unknown",
                "source": f.get("file_name") or "unknown",
                "storage_uri": f.get("file_url"),
            }
            for f in files
        ],
        "timestamps": {
            "created_at": run_ctx["created_at"],
            "completed_at": run_ctx.get("completed_at"),
        },
        "raw": pipeline_result,
    }


def _build_sync_report(text: str, files: list[dict], pipeline_result: dict, primary_type: str) -> dict:
    _, selected_agents, _skipped = _classify_flow({"text": text, "files": files})
    now = _utc_now()
    run_ctx = {
        "run_id": str(pipeline_result.get("acknowledgment_id") or _new_id("run")),
        "case_id": str(pipeline_result.get("case_id") or _new_id("case")),
        "status": "completed",
        "created_at": now,
        "completed_at": now,
        "request": {
            "user_input": {
                "text": text,
                "files": files,
            }
        },
        "similar_patterns_count": int(pipeline_result.get("similar_cases_found") or 0),
    }
    return _build_result_document(run_ctx, pipeline_result, primary_type, selected_agents)


async def _orchestrate_run(run_id: str) -> None:
    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        return

    try:
        run_ctx["status"] = "running"
        req = run_ctx["request"]
        user_input = req["user_input"]
        user_context = req.get("user_context") if isinstance(req.get("user_context"), dict) else {}
        session_id = str(req.get("session_id") or "") or None
        request_options = (req.get("options") or {}) if isinstance(req.get("options"), dict) else {}

        primary_type, selected_agents, skipped_agents = _classify_flow(user_input)
        run_ctx["primary_type"] = primary_type
        run_ctx["selected_agents"] = selected_agents

        await _emit_event(
            run_id,
            "run.classified",
            {
                "case_id": run_ctx["case_id"],
                "primary_type": primary_type,
                "selected_agents": selected_agents,
                "skipped_agents": [{"agent": a, "reason": r} for a, r in skipped_agents],
            },
        )

        for agent_name, reason in skipped_agents:
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": agent_name,
                    "status": "skipped",
                    "output": {"summary": f"Skipped: {reason}", "reason": reason},
                },
            )

        await _emit_event(run_id, "agent.started", {"agent": "manager", "label": "Manager Agent", "status": "booting"})
        await _emit_event(
            run_id,
            "agent.progress",
            {
                "agent": "manager",
                "step": "route_planning",
                "status": "running",
                "message": "Manager selected execution graph",
            },
        )

        for agent in selected_agents:
            if agent == "manager":
                continue
            await _emit_event(
                run_id,
                "agent.started",
                {"agent": agent, "label": agent.replace("_", " ").title(), "status": "queued"},
            )

        await _emit_event(
            run_id,
            "tool.called",
            {
                "agent": "manager",
                "tool": "manager_pipeline",
                "message": "Manager delegating to selected agents",
            },
        )

        user_text = str(user_input.get("text") or "").strip()
        similar_patterns: list[dict] = []
        if user_text:
            await _emit_event(
                run_id,
                "tool.called",
                {
                    "agent": "manager",
                    "tool": "vector_pattern_lookup",
                    "message": "Searching similar historical fraud patterns",
                },
            )
            similar_patterns = find_similar_patterns(
                query_text=user_text,
                scam_type=None,
                limit=3,
                min_score=25,
            )
            await _emit_event(
                run_id,
                "tool.result",
                {
                    "agent": "manager",
                    "tool": "vector_pattern_lookup",
                    "status": "ok",
                    "matches": len(similar_patterns),
                },
            )
        run_ctx["similar_patterns_count"] = len(similar_patterns)
        run_ctx["similar_patterns"] = similar_patterns

        input_type, payload = _build_pipeline_call(
            user_input,
            similar_patterns,
            session_id=session_id,
            options=request_options,
            user_context=user_context,
            fraud_amount=float(request_options.get("fraud_amount") or 0),
            minutes_since_fraud=_bucket_to_minutes(request_options.get("time_bucket")),
        )
        legacy_input = _build_legacy_input(user_input)

        pipeline_timeout_s = 0.0
        try:
            pipeline_timeout_s = float(os.getenv("SATARK_ADK_PIPELINE_TIMEOUT_S", "120"))
        except Exception:
            pipeline_timeout_s = 120.0

        if run_pipeline is None:
            await _emit_event(
                run_id,
                "tool.called",
                {
                    "agent": "manager",
                    "tool": "legacy_manager_pipeline",
                    "message": "Primary pipeline unavailable, activating fallback inference path",
                },
            )
            pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
            await _emit_event(
                run_id,
                "tool.result",
                {
                    "agent": "manager",
                    "tool": "legacy_manager_pipeline",
                    "status": "ok",
                },
            )
        else:
            try:
                if pipeline_timeout_s and pipeline_timeout_s > 0:
                    pipeline_result = await asyncio.wait_for(
                        run_pipeline(input_type, payload),
                        timeout=pipeline_timeout_s,
                    )
                else:
                    pipeline_result = await run_pipeline(input_type, payload)
            except asyncio.TimeoutError:
                await _emit_event(
                    run_id,
                    "tool.result",
                    {
                        "agent": "manager",
                        "tool": "manager_pipeline",
                        "status": "timeout",
                        "error": f"Primary pipeline exceeded {pipeline_timeout_s:.0f}s; falling back",
                    },
                )
                await _emit_event(
                    run_id,
                    "tool.called",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "message": "Primary pipeline timed out, activating fallback inference path",
                    },
                )
                pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
                await _emit_event(
                    run_id,
                    "tool.result",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "status": "ok",
                    },
                )
            except Exception:
                await _emit_event(
                    run_id,
                    "tool.called",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "message": "Primary pipeline errored, activating fallback inference path",
                    },
                )
                pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
                await _emit_event(
                    run_id,
                    "tool.result",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "status": "ok",
                    },
                )

            if _needs_legacy_fallback(pipeline_result):
                await _emit_event(
                    run_id,
                    "tool.called",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "message": "Primary pipeline degraded, activating fallback inference path",
                    },
                )
                pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
                await _emit_event(
                    run_id,
                    "tool.result",
                    {
                        "agent": "manager",
                        "tool": "legacy_manager_pipeline",
                        "status": "ok",
                    },
                )

        await _emit_event(
            run_id,
            "tool.result",
            {
                "agent": "manager",
                "tool": "manager_pipeline",
                "status": "ok",
            },
        )

        backend_requires_mcp = bool(
            isinstance(pipeline_result, dict)
            and pipeline_result.get("requires_mcp")
        )

        if backend_requires_mcp:
            calendar_event = pipeline_result.get("calendar_event") if isinstance(pipeline_result.get("calendar_event"), dict) else {}
            cal_created = bool(calendar_event.get("created"))
            cal_attempted = bool(calendar_event.get("attempted"))
            cal_error = str(calendar_event.get("error") or "").strip()
            cal_start = str(calendar_event.get("start_time") or "").strip()
            cal_url = str(
                calendar_event.get("deep_link")
                or calendar_event.get("event_url")
                or calendar_event.get("html_link")
                or calendar_event.get("url")
                or ""
            ).strip()
            cal_summary = "Scheduled" if cal_created else ("Failed" if cal_attempted else "Skipped")
            if cal_start:
                cal_summary = f"{cal_summary} ({cal_start})"
            if cal_error and not cal_created:
                cal_summary = f"{cal_summary} — {cal_error}"
            cal_status = "done" if cal_created else ("failed" if cal_attempted and cal_error else "skipped")
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": "google_calendar",
                    "status": cal_status,
                    "output": {
                        "summary": cal_summary,
                        "deep_link": cal_url or None,
                        "url": cal_url or None,
                    },
                },
            )

            tasks_payload = pipeline_result.get("google_tasks") if isinstance(pipeline_result.get("google_tasks"), dict) else {}
            tasks_created = bool(tasks_payload.get("created"))
            tasks_error = str(tasks_payload.get("error") or "").strip()
            tasks_url = str(tasks_payload.get("task_url") or tasks_payload.get("deep_link") or tasks_payload.get("url") or "").strip()
            tasks_summary = "Checklist ready" if tasks_created else ("Failed" if tasks_error else "Skipped")
            if tasks_error and not tasks_created:
                tasks_summary = f"{tasks_summary} — {tasks_error}"
            tasks_status = "done" if tasks_created else ("failed" if tasks_error else "skipped")
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": "google_tasks",
                    "status": tasks_status,
                    "output": {
                        "summary": tasks_summary,
                        "deep_link": tasks_url or None,
                        "url": tasks_url or None,
                    },
                },
            )

            doc_payload = pipeline_result.get("case_report_doc") if isinstance(pipeline_result.get("case_report_doc"), dict) else {}
            doc_created = bool(doc_payload.get("created")) or bool(doc_payload.get("doc_url"))
            doc_error = str(doc_payload.get("error") or "").strip()
            doc_url = str(doc_payload.get("doc_url") or doc_payload.get("deep_link") or doc_payload.get("url") or "").strip()
            doc_summary = "Case report ready" if doc_created else ("Failed" if doc_error else "Skipped")
            if doc_error and not doc_created:
                doc_summary = f"{doc_summary} — {doc_error}"
            doc_status = "done" if doc_created else ("failed" if doc_error else "skipped")
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": "google_docs",
                    "status": doc_status,
                    "output": {
                        "summary": doc_summary,
                        "deep_link": doc_url or None,
                        "url": doc_url or None,
                    },
                },
            )

            gmail_payload = pipeline_result.get("gmail_draft") if isinstance(pipeline_result.get("gmail_draft"), dict) else {}
            gmail_created = bool(gmail_payload.get("created")) or bool(gmail_payload.get("draft_url"))
            gmail_error = str(gmail_payload.get("error") or "").strip()
            gmail_url = str(gmail_payload.get("draft_url") or gmail_payload.get("deep_link") or gmail_payload.get("url") or "").strip()
            gmail_summary = "Draft ready" if gmail_created else ("Failed" if gmail_error else "Skipped")
            if gmail_error and not gmail_created:
                gmail_summary = f"{gmail_summary} — {gmail_error}"
            gmail_status = "done" if gmail_created else ("failed" if gmail_error else "skipped")
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": "google_gmail",
                    "status": gmail_status,
                    "output": {
                        "summary": gmail_summary,
                        "deep_link": gmail_url or None,
                        "url": gmail_url or None,
                    },
                },
            )

        for agent in selected_agents:
            if agent == "manager":
                continue
            summary = "Stage completed"
            if agent == "scam_detector":
                summary = f"Risk {pipeline_result.get('risk_level', 'UNKNOWN')} | type {pipeline_result.get('scam_type', 'UNKNOWN')}"
            elif agent == "osint":
                summary = pipeline_result.get("osint_summary", "OSINT correlation complete") or "OSINT complete"
            elif agent == "golden_hour":
                summary = "Priority response actions generated"
            await _emit_event(
                run_id,
                "agent.completed",
                {
                    "agent": agent,
                    "status": "done",
                    "output": {
                        "summary": summary,
                    },
                },
            )

        await _emit_event(
            run_id,
            "agent.completed",
            {
                "agent": "manager",
                "status": "done",
                "output": {
                    "summary": "Routing and orchestration complete",
                },
            },
        )

        run_ctx["status"] = "completed"
        run_ctx["completed_at"] = _utc_now()

        # Prefer pipeline-emitted retrieval results for user-visible counts.
        try:
            if isinstance(pipeline_result, dict):
                run_ctx["similar_patterns_count"] = int(pipeline_result.get("similar_cases_found") or run_ctx.get("similar_patterns_count") or 0)
                if isinstance(pipeline_result.get("pattern_matches"), list):
                    run_ctx["similar_patterns"] = pipeline_result.get("pattern_matches")
        except Exception:
            pass
        run_ctx["result"] = _build_result_document(run_ctx, pipeline_result, primary_type, selected_agents)

        result = run_ctx["result"]
        scam_type = str(result.get("scam_type") or "UNKNOWN")
        risk_level = str(result.get("risk_level") or "UNKNOWN")
        confidence = float(result.get("confidence") or 0)
        input_type = str(result.get("input_type") or primary_type)
        golden_hour_active = str(result.get("golden_hour_status") or "").upper() == "ACTIVE"
        summary_text = str(result.get("summary") or "")

        # Persist the full pipeline output so /api/result/{case_id} can reload
        # Tasks/Docs links and evidence for historical runs.
        if isinstance(pipeline_result, dict):
            if not pipeline_result.get("case_id"):
                pipeline_result["case_id"] = run_ctx.get("case_id") or run_id
            if not pipeline_result.get("acknowledgment_id"):
                pipeline_result["acknowledgment_id"] = run_id
        save_case(acknowledgment_id=run_id, case_data=pipeline_result if isinstance(pipeline_result, dict) else {})

        final_user_text = user_text
        final_scam_type = scam_type
        final_confidence = float(confidence or 0)
        if final_user_text and final_scam_type.upper() not in {"UNKNOWN", "NONE", ""}:
            save_fraud_pattern(final_user_text, final_scam_type, final_confidence)

        await _emit_event(
            run_id,
            "run.completed",
            {
                "case_id": run_ctx["case_id"],
                "result_url": f"/api/result/{run_id}",
            },
        )
    except Exception as e:
        run_ctx["status"] = "failed"
        run_ctx["completed_at"] = _utc_now()
        run_ctx["error"] = str(e)
        await _emit_event(
            run_id,
            "run.failed",
            {
                "case_id": run_ctx["case_id"],
                "error": str(e),
            },
        )
    finally:
        await _finish_streams(run_id)

class TextRequest(BaseModel):
    text: str
    fraud_amount: Optional[float] = 0
    minutes_since_fraud: Optional[int] = None

@app.get("/api")
def api_root():
    return {
        "service": "SATARK AI",
        "status": "online",
        "version": "1.0.0",
        "helpline": "1930",
        "portal": "cybercrime.gov.in",
    }

@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/api/health")
def api_health():
    return {
        "status": "healthy",
        "service": "satark-api",
        "timestamp": _utc_now(),
    }


@app.post("/api/analyze/preprocess")
async def api_analyze_preprocess(req: PreprocessRequest):
    user_input = req.user_input.model_dump()
    context = await _build_preprocessed_context(user_input)
    return {
        "status": "ready",
        "session_id": req.session_id,
        "context": context,
    }


@app.post("/api/analyze")
async def api_analyze(req: AnalyzeRequestV1):
    run_id = _new_id("run")
    case_id = _new_id("case")

    session_id = req.session_id or _new_id("sess")
    req_payload = req.model_dump()
    req_payload["session_id"] = session_id

    RUN_STORE[run_id] = {
        "run_id": run_id,
        "case_id": case_id,
        "status": "accepted",
        "created_at": _utc_now(),
        "completed_at": None,
        "request": req_payload,
        "result": None,
        "error": None,
        "events": [],
        "subscribers": [],
    }

    await _emit_event(
        run_id,
        "run.accepted",
        {
            "case_id": case_id,
            "status": "accepted",
        },
    )

    asyncio.create_task(_orchestrate_run(run_id))

    return {
        "run_id": run_id,
        "case_id": case_id,
        "session_id": session_id,
        "status": "accepted",
        "stream_url": f"/api/stream/{run_id}",
        "result_url": f"/api/result/{run_id}",
    }


@app.get("/api/stream/{run_id}")
async def api_stream(run_id: str):
    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        raise HTTPException(status_code=404, detail="run_id not found")

    queue: asyncio.Queue = asyncio.Queue()
    history = list(run_ctx.get("events", []))
    run_ctx.setdefault("subscribers", []).append(queue)

    async def stream_generator():
        try:
            for evt in history:
                yield _event_line(evt["event"], evt["data"])

            while True:
                current = RUN_STORE.get(run_id) or {}
                if current.get("status") in {"completed", "failed"} and queue.empty():
                    break
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue

                if evt is None:
                    break
                yield _event_line(evt["event"], evt["data"])
        finally:
            latest = RUN_STORE.get(run_id)
            if latest and queue in latest.get("subscribers", []):
                latest["subscribers"].remove(queue)

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/result/{run_id}")
async def api_result(run_id: str):
    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        persisted = _load_persisted_case(run_id)
        if persisted is None:
            raise HTTPException(status_code=404, detail="run_id not found")
        return persisted

    status = run_ctx.get("status")
    if status in {"accepted", "running"}:
        return JSONResponse(
            status_code=202,
            content={
                "run_id": run_id,
                "case_id": run_ctx.get("case_id"),
                "status": status,
                "message": "Run still in progress",
            },
        )

    if status == "failed":
        return {
            "run_id": run_id,
            "case_id": run_ctx.get("case_id"),
            "status": "failed",
            "error": run_ctx.get("error", "Unknown error"),
            "timestamps": {
                "created_at": run_ctx.get("created_at"),
                "completed_at": run_ctx.get("completed_at"),
            },
        }

    return run_ctx.get("result")


@app.post("/api/recovery/finalize")
async def api_recovery_finalize(req: RecoveryFinalizeRequest):
    run_id = str(req.run_id or "").strip()
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")

    run_ctx = RUN_STORE.get(run_id)
    if not run_ctx:
        raise HTTPException(status_code=404, detail="run_id not found")

    status = str(run_ctx.get("status") or "")
    if status in {"accepted", "running"}:
        return JSONResponse(
            status_code=202,
            content={
                "run_id": run_id,
                "case_id": run_ctx.get("case_id"),
                "status": status,
                "message": "Run still in progress",
            },
        )
    if status == "failed":
        raise HTTPException(status_code=400, detail="analysis run failed")

    reactive = bool(req.did_lose_money_or_share_bank_details)
    amount_lost = max(0.0, float(req.amount_lost or 0))
    time_bucket = str(req.time_bucket or "").strip().lower() or None
    explicit_report = bool(req.explicit_report_request)
    minutes_since = _bucket_to_minutes(time_bucket)

    run_ctx["recovery_answers"] = {
        "did_lose_money_or_share_bank_details": reactive,
        "amount_lost": amount_lost,
        "time_bucket": time_bucket,
        "minutes_since_incident": minutes_since,
        "explicit_report_request": explicit_report,
    }

    req_payload = run_ctx.get("request") if isinstance(run_ctx.get("request"), dict) else {}
    user_input = req_payload.get("user_input") if isinstance(req_payload.get("user_input"), dict) else {}
    request_options = req_payload.get("options") if isinstance(req_payload.get("options"), dict) else {}
    session_id = str(req_payload.get("session_id") or "") or None

    options = dict(request_options)
    options.update(
        {
            "trigger_mcp_actions": bool(reactive or explicit_report),
            "recovery_mode": "reactive" if reactive else "proactive",
            "fraud_amount": amount_lost,
            "time_bucket": time_bucket,
            "recovery_answers": run_ctx["recovery_answers"],
        }
    )

    similar_patterns = run_ctx.get("similar_patterns") if isinstance(run_ctx.get("similar_patterns"), list) else []
    input_type, payload = _build_pipeline_call(
        user_input,
        similar_patterns,
        session_id=session_id,
        options=options,
        fraud_amount=amount_lost,
        minutes_since_fraud=minutes_since,
    )

    if run_pipeline is None:
        legacy_input = _build_legacy_input(user_input)
        pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)
    else:
        pipeline_result = await run_pipeline(input_type, payload)
        if _needs_legacy_fallback(pipeline_result):
            legacy_input = _build_legacy_input(user_input)
            pipeline_result = await asyncio.to_thread(run_legacy_pipeline, legacy_input)

    primary_type, selected_agents, _skipped = _classify_flow(user_input)
    run_ctx["status"] = "completed"
    run_ctx["completed_at"] = _utc_now()
    run_ctx["similar_patterns_count"] = len(similar_patterns)
    run_ctx["result"] = _build_result_document(run_ctx, pipeline_result, primary_type, selected_agents)
    if isinstance(run_ctx.get("result"), dict):
        run_ctx["result"]["user_recovery_answers"] = dict(run_ctx.get("recovery_answers") or {})

    if isinstance(pipeline_result, dict):
        if not pipeline_result.get("case_id"):
            pipeline_result["case_id"] = run_ctx.get("case_id") or run_id
        if not pipeline_result.get("acknowledgment_id"):
            pipeline_result["acknowledgment_id"] = run_id
    save_case(acknowledgment_id=run_id, case_data=pipeline_result if isinstance(pipeline_result, dict) else {})

    return run_ctx["result"]


@app.get("/api/cases")
def get_cases():
    from db.operations import get_recent_cases
    return get_recent_cases(10)
@app.get("/stats")
def stats():
    return get_case_stats()


@app.post("/analyze")
async def analyze_unified(
    text: Optional[str] = Form(None),
    file: UploadFile | None = File(None),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None),
):
    try:
        if file is None and (text is None or not text.strip()):
            raise HTTPException(status_code=400, detail="Provide text and/or file")

        if file is None:
            result = await run_pipeline(
                "text",
                {
                    "text": (text or "").strip(),
                    "fraud_amount": fraud_amount,
                    "minutes_since_fraud": minutes_since_fraud,
                },
            )
            report = _build_sync_report(
                text=(text or "").strip(),
                files=[],
                pipeline_result=result,
                primary_type="text",
            )
            return JSONResponse(content=report)

        content = await file.read()
        filename = file.filename or "uploaded_file"
        mime_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

        if ext == "apk" or mime_type == "application/vnd.android.package-archive":
            from agents.apk_analyzer.agent import run_static_analysis

            static_results = run_static_analysis(content, filename)
            result = await run_pipeline(
                "apk",
                {
                    "filename": filename,
                    "static_results": static_results,
                    "text": (text or "").strip(),
                },
            )
            report = _build_sync_report(
                text=(text or "").strip(),
                files=[{"file_name": filename, "file_type": mime_type}],
                pipeline_result=result,
                primary_type="apk",
            )
            return JSONResponse(content=report)

        if mime_type.startswith("audio/"):
            audio_b64 = base64.b64encode(content).decode("utf-8")
            result = await run_pipeline(
                "audio",
                {
                    "audio_b64": audio_b64,
                    "filename": filename,
                    "mime_type": mime_type,
                    "text": (text or "").strip(),
                    "fraud_amount": fraud_amount,
                    "minutes_since_fraud": minutes_since_fraud,
                },
            )
            report = _build_sync_report(
                text=(text or "").strip(),
                files=[{"file_name": filename, "file_type": mime_type}],
                pipeline_result=result,
                primary_type="audio",
            )
            return JSONResponse(content=report)

        image_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline(
            "image",
            {
                "image_b64": image_b64,
                "filename": filename,
                "mime_type": mime_type,
                "text": (text or "").strip(),
                "fraud_amount": fraud_amount,
                "minutes_since_fraud": minutes_since_fraud,
            },
        )
        report = _build_sync_report(
            text=(text or "").strip(),
            files=[{"file_name": filename, "file_type": mime_type}],
            pipeline_result=result,
            primary_type="text_image",
        )
        return JSONResponse(content=report)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/text")
async def analyze_text(req: TextRequest):
    try:
        result = await run_pipeline("text", {
            "text": req.text,
            "fraud_amount": req.fraud_amount,
            "minutes_since_fraud": req.minutes_since_fraud,
        })
        report = _build_sync_report(req.text, [], result, "text")
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/image")
async def analyze_image(
    file: UploadFile = File(...),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None)
):
    try:
        content = await file.read()
        image_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline("image", {
            "image_b64": image_b64,
            "filename": file.filename,
            "mime_type": file.content_type or "image/jpeg",
            "fraud_amount": fraud_amount,
            "minutes_since_fraud": minutes_since_fraud,
        })
        report = _build_sync_report(
            "",
            [{"file_name": file.filename or "upload.jpg", "file_type": file.content_type or "image/jpeg"}],
            result,
            "text_image",
        )
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/audio")
async def analyze_audio(
    file: UploadFile = File(...),
    fraud_amount: float = Form(0),
    minutes_since_fraud: Optional[int] = Form(None)
):
    try:
        content = await file.read()
        audio_b64 = base64.b64encode(content).decode("utf-8")
        result = await run_pipeline("audio", {
            "audio_b64": audio_b64,
            "filename": file.filename,
            "mime_type": file.content_type or "audio/mp3",
            "fraud_amount": fraud_amount,
            "minutes_since_fraud": minutes_since_fraud,
        })
        report = _build_sync_report(
            "",
            [{"file_name": file.filename or "upload.audio", "file_type": file.content_type or "audio/mp3"}],
            result,
            "audio",
        )
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/apk")
async def analyze_apk(file: UploadFile = File(...)):
    try:
        content = await file.read()
        from agents.apk_analyzer.agent import run_static_analysis
        static_results = run_static_analysis(content, file.filename)
        result = await run_pipeline("apk", {
            "filename": file.filename,
            "static_results": static_results,
        })
        report = _build_sync_report(
            "",
            [{"file_name": file.filename or "upload.apk", "file_type": file.content_type or "application/vnd.android.package-archive"}],
            result,
            "apk",
        )
        return JSONResponse(content=report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/stream")
async def stream_audio(websocket: WebSocket):
    await websocket.accept()

    if live_client is None or genai_types is None:
        await websocket.send_json({"type": "error", "message": "google-genai live SDK is unavailable"})
        await websocket.close(code=1011)
        return

    model_name = GEMINI_LIVE_MODEL
    mime_type = "audio/webm"
    stop_event = asyncio.Event()

    try:
        async with live_client.aio.live.connect(
            model=model_name,
            config={
                "response_modalities": ["AUDIO"],
                "input_audio_transcription": {},
                "output_audio_transcription": {},
            },
        ) as session:
            await session.send_client_content(
                turns={"role": "user", "parts": [{"text": LIVE_STREAM_INSTRUCTION}]},
                turn_complete=False,
            )

            async def receive_browser_audio():
                nonlocal mime_type
                while not stop_event.is_set():
                    message = await websocket.receive()

                    if message.get("type") == "websocket.disconnect":
                        stop_event.set()
                        break

                    if message.get("bytes") is not None:
                        chunk = message["bytes"]
                        if chunk:
                            await session.send_realtime_input(
                                audio=genai_types.Blob(data=chunk, mime_type=mime_type)
                            )
                        continue

                    text_msg = (message.get("text") or "").strip()
                    if not text_msg:
                        continue

                    try:
                        payload = json.loads(text_msg)
                    except Exception:
                        await session.send_realtime_input(text=text_msg)
                        continue

                    event_type = payload.get("type")
                    if event_type == "config" and payload.get("mime_type"):
                        mime_type = str(payload.get("mime_type"))
                    elif event_type == "audio_end":
                        await session.send_realtime_input(audio_stream_end=True)
                    elif event_type == "text" and payload.get("text"):
                        await session.send_realtime_input(text=str(payload.get("text")))

                stop_event.set()

            async def forward_live_analysis():
                while not stop_event.is_set():
                    async for chunk in session.receive():
                        if chunk.text:
                            await websocket.send_json({"type": "analysis", "text": chunk.text})
                        if (
                            chunk.server_content
                            and chunk.server_content.input_transcription
                            and chunk.server_content.input_transcription.text
                        ):
                            await websocket.send_json(
                                {
                                    "type": "analysis",
                                    "text": f"CALLER: {chunk.server_content.input_transcription.text}",
                                }
                            )
                        if (
                            chunk.server_content
                            and chunk.server_content.output_transcription
                            and chunk.server_content.output_transcription.text
                        ):
                            await websocket.send_json(
                                {
                                    "type": "analysis",
                                    "text": f"SATARK: {chunk.server_content.output_transcription.text}",
                                }
                            )
                        if chunk.server_content and chunk.server_content.turn_complete:
                            await websocket.send_json({"type": "turn_complete"})
                        if stop_event.is_set():
                            break

                stop_event.set()

            in_task = asyncio.create_task(receive_browser_audio())
            out_task = asyncio.create_task(forward_live_analysis())

            done, pending = await asyncio.wait(
                [in_task, out_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            stop_event.set()

            for task in pending:
                task.cancel()

            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, WebSocketDisconnect):
                    await websocket.send_json({"type": "error", "message": str(exc)})

            try:
                await session.send_realtime_input(audio_stream_end=True)
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("api.main:app", host="0.0.0.0", port=port)