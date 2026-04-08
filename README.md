# SATARK AI

Smart Anti-fraud Technology for Awareness, Reporting and Knowledge.

SATARK AI is a multi-agent cybercrime response system inspired by real public-facing fraud workflows in India. The goal is simple: help a victim move from confusion to action within minutes, not hours.

Instead of forcing victims to navigate fragmented tools, SATARK AI accepts text, screenshots, audio, and APK files in one flow, investigates the threat, and generates immediate action guidance with a case reference.

## Why This Matters

Cyber fraud response is a race against time. The first hour after a fraud event is often the highest-leverage window for fund recovery and evidence preservation.

SATARK AI is designed as a citizen-accessible, 24x7, low-friction digital layer that mirrors specialist investigation steps:

- classify the incident quickly
- investigate indicators with OSINT
- assess risk and pattern similarity
- generate FIR-ready guidance and urgent next actions

## Real-World User Stories

- A grandmother in Warangal receives a WhatsApp message claiming her bank account will be blocked.
- A college student installs a Telegram APK claiming to be a free premium app.
- A working professional transfers money after a fake bank fraud-department call.

All three can submit evidence and receive a structured investigation response in under a minute in the happy path.

## Architecture Overview

SATARK AI has two major layers:

1. Web interface
- Minimal input-first UX served by FastAPI at the UI route.
- Supports typed text, attachments, and live voice stream mode.

2. Multi-agent backend engine
- Python FastAPI API.
- ADK-style manager pipeline for orchestration, with explicit A2A handoff metadata.
- Specialized agents for scam classification, APK analysis, audio/vishing analysis, OSINT enrichment, and golden-hour response planning.
- Firestore-backed operational data and pattern intelligence collections.

## Agent System (6 Roles)

### 1) Manager Agent

Purpose: intake, routing, and orchestration.

What it does:
- accepts normalized input from API
- selects the correct primary detection agent by modality
- triggers follow-up OSINT and response-planning in parallel when applicable
- emits A2A handoff envelopes for traceable inter-agent communication

### 2) Scam Detector Agent

Purpose: fraud signal extraction and structured classification from text/image context.

What it does:
- identifies urgency, impersonation, OTP harvesting, link-based lures, and pressure tactics
- produces structured output with scam type, confidence, risk level, entities, and victim advice

### 3) Audio Analyzer Agent

Purpose: vishing-focused analysis of uploaded audio evidence.

What it does:
- analyzes call/voice-note content for social engineering patterns
- extracts impersonation cues, urgency markers, and actionable risk

### 4) APK Analyzer Agent

Purpose: static mobile threat triage.

What it does:
- computes APK hash and scans package structure
- extracts potential hardcoded IPs/URLs and suspicious strings
- flags likely malicious infrastructure candidates for escalation

### 5) OSINT Agent

Purpose: indicator enrichment and infrastructure-level risk scoring.

What it does:
- performs WHOIS, reverse IP, ASN, certificate transparency, URL reputation, and abuse checks
- synthesizes law-enforcement-style threat summaries
- assigns an aggregate threat score

### 6) Golden Hour Response Agent

Purpose: immediate action playbook and complaint readiness.

What it does:
- generates priority actions with deadlines
- prepares FIR-oriented summary output
- can create a real Google Calendar reminder event for urgent complaint filing

## What Is Implemented Today

- Unified analyze endpoint for text, image, audio, and APK submissions.
- Live WebSocket stream route for microphone-to-model fraud analysis updates.
- Real-time browser capture using MediaRecorder and streamed server responses.
- A2A handoff envelopes across manager and specialist agents.
- Firestore native vector search for fraud pattern similarity (nearest-neighbor retrieval).
- Golden Hour response generation with calendar event integration.
- Session stats and case-oriented output in UI.

## Roadmap Extensions

The following are valid next-phase upgrades and can be demoed as planned capability:

- automated email draft delivery workflow
- richer law-enforcement dashboard feed
- deeper APK decompilation intelligence integration
- expanded multilingual personalization of victim guidance

## Tech Stack

- Python 3.12
- FastAPI + Uvicorn
- Google ADK components
- Google GenAI SDK and Vertex AI models
- Firestore for operational persistence
- Web-risk and external OSINT utilities
- HTML/CSS/JS frontend

## Data Model Concept

The platform behavior maps to four operational intelligence buckets:

- fraud_patterns: recurring scam signatures and trigger phrases
- threat_intelligence: indicators and linked enrichment outputs
- cases: case-level audit entries and response snapshots
- osint_cache: cached enrichment results for speed and cost control

## API Surface

- UI and health:
  - GET /ui
  - GET /ops
  - GET /api
  - GET /health
  - GET /api/health
- Auth:
  - GET /auth/google/start
  - GET /auth/google/callback
  - GET /auth/google/logout
  - GET /api/auth/status
- Two-phase analyze API (recommended):
  - POST /api/analyze/preprocess
  - POST /api/analyze
  - POST /api/analyze/deep
  - GET /api/stream/{run_id}
  - GET /api/result/{run_id}
  - GET /api/debug/timings/{run_id}
  - POST /api/recovery/finalize
  - GET /api/cases
- Productivity workflow API:
  - POST /workflow/run
  - GET /workflow/{workflow_id}
  - GET /workflow/{workflow_id}/stream
- Legacy compatibility routes:
  - GET /stats
  - POST /analyze
  - POST /analyze/text
  - POST /analyze/image
  - POST /analyze/audio
  - POST /analyze/apk
  - WS /stream

## Regression Lock: Calm Vs Urgent

Citizen behavior is now locked and treated as a regression gate.

- Prevented scam case must stay calm:
  - `requires_reporting = false`
  - `requires_emergency = false`
  - no report-now or emergency language
- Money-lost case must stay urgent:
  - `requires_reporting = true`
  - `requires_emergency = true`
  - clear report-now guidance

Baseline artifacts:

- `artifacts/ui-acceptance/prevented-scam.png`
- `artifacts/ui-acceptance/money-lost.png`
- `artifacts/ui-acceptance/prevented-vs-moneylost-side-by-side.png`

Regression fixtures:

- `artifacts/regression-fixtures/prevented_scam.json`
- `artifacts/regression-fixtures/money_lost.json`
- `artifacts/regression-fixtures/apk_known_training.json`
- `artifacts/regression-fixtures/apk_malicious_like.json`
- `artifacts/regression-fixtures/apk_benign_like.json`

Run the automated check:

```bash
python scripts/regression/check_calm_vs_urgent.py
```

Run the chat-reply tone contract check (preventive SMS + APK + UI source-of-truth):

```bash
python scripts/regression/check_chat_reply_contract.py
```

Run deterministic APK fixture profile checks (known training app vs malicious-like vs benign-like):

```bash
python scripts/regression/check_apk_fixture_profiles.py
```

If this script fails, treat it as a release blocker.

### Google Sign-In (Calendar)

To make the judge demo "real" (Calendar reminder lands in the judge's own account), SATARK includes a minimal OAuth flow:

- GET `/auth/google/start?session_id=...&next=/ui` (redirects to Google consent)
- GET `/auth/google/callback` (exchanges code for tokens and stores them in Firestore under that `session_id`)

Required env vars:

- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (OAuth Web client)
- `SATARK_AUTH_STATE_SECRET` (HMAC secret to sign the OAuth `state`)
- Optional: `SATARK_PUBLIC_BASE_URL` (recommended on Cloud Run so redirect URIs are stable)

Troubleshooting: **"Access blocked" / `403: access_denied`**

If Google shows a screen like "Access blocked: … has not completed the Google verification process", this is almost always **OAuth Consent Screen** configuration:

1) In Google Cloud Console → **APIs & Services → OAuth consent screen**
- Set **User type** to **External** (unless you are using a Google Workspace org and want Internal-only).
- Keep **Publishing status** as **Testing** for hackathons.
- Add the Google account(s) you will sign in with under **Test users** (include judges if you want them to sign in).

2) In Google Cloud Console → **APIs & Services → Credentials → OAuth 2.0 Client IDs**
- Client type must be **Web application**.
- Add Authorized redirect URIs exactly (hostnames must match):
  - `http://127.0.0.1:8080/auth/google/callback` (local)
  - `https://YOUR_CLOUD_RUN_URL/auth/google/callback` (Cloud Run)

Note: the app requests `https://www.googleapis.com/auth/calendar.events` (Calendar write). For broad public access in production you may need Google verification; for hackathon demos, **Testing + Test users** is the fastest path.

## Minimal End-to-End Demo (Curl)

This repo contains two demo-friendly flows:

1) **Productivity workflow** (tasks + notes + proposed schedule) with optional MCP sync.
2) **Fraud workflow** (scam detection + OSINT + golden-hour response) with Google Calendar MCP.

### 1) Productivity workflow (tasks, notes, schedule)

Run:

```bash
curl -s http://127.0.0.1:8080/workflow/run \
  -H 'content-type: application/json' \
  -d '{
    "user_id": "demo_user",
    "goal": "Plan next week: finish the hackathon deck, schedule a mentor call, and write a 1-page demo script.",
    "context": {"timezone": "Asia/Kolkata"},
    "options": {"auto_execute_tools": true, "stream": true}
  }'
```

Then poll the `workflow_url` from the response until it returns `status: completed`.

Notes:
- Firestore persistence happens automatically.
- If Google Calendar MCP credentials are configured, calendar blocks can be created via MCP.
- Notes/tasks MCP sync is **optional** and can be enabled by setting `SATARK_NOTES_*` / `SATARK_TASKS_*` env vars.

### 2) Fraud analysis (golden hour + calendar reminder)

```bash
curl -s http://127.0.0.1:8080/analyze/text \
  -H 'content-type: application/json' \
  -d '{
    "text": "URGENT: Your KYC is pending. Click http://kyc-update-now.example to avoid account block. Share OTP to verify.",
    "fraud_amount": 0,
    "minutes_since_fraud": 20
  }'
```

If MCP auth is configured, the Golden Hour agent may create a real Calendar reminder event.

Tip: open `/ui`, click "Sign in with Google (Calendar)", then run an analysis that triggers `golden_hour_active=true`.

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies from requirements.
3. Configure environment variables in .env for GCP project/location and credentials.
4. Run the API server.

Example:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn api.main:app --reload --port 8080
```

Open:

- http://127.0.0.1:8080/ui

## Docker / Cloud Run

This repo includes a minimal Dockerfile that also installs Node/npm (required for MCP stdio servers invoked via `npx`).

### Build + run locally

```bash
docker build -t satark-ai .
docker run --rm -p 8080:8080 \
  -e GOOGLE_CLOUD_PROJECT=YOUR_PROJECT \
  -e GOOGLE_CLOUD_LOCATION=us-central1 \
  -e GOOGLE_OAUTH_CREDENTIALS=/app/credentials/oauth.json \
  satark-ai
```

### Deploy to Cloud Run (example)

```bash
gcloud run deploy satark-ai \
  --source . \
  --region us-central1 \
  --allow-unauthenticated
```

Then set required environment variables in Cloud Run (Service → Edit & deploy new revision → Variables & secrets).

## Environment Variables

Minimum recommended:

- GOOGLE_CLOUD_PROJECT
- GOOGLE_CLOUD_LOCATION
- GOOGLE_APPLICATION_CREDENTIALS (or equivalent ADC path)
- GEMINI_API_KEY (only for components running API-key mode)
- GOOGLE_CALENDAR_ID (optional, defaults to primary)
- SATARK_CALENDAR_TIMEZONE (optional, defaults to Asia/Kolkata)

MCP Google tool auth required by Golden Hour agent:

- GOOGLE_OAUTH_CREDENTIALS (absolute path to OAuth desktop credentials JSON)

Alternative auth mode (if your MCP server supports refresh tokens):

- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- GOOGLE_REFRESH_TOKEN

Calendar MCP (optional overrides):

- `SATARK_CALENDAR_MCP_COMMAND` (default: `npx`)
- `SATARK_CALENDAR_MCP_ARGS` (default: `["-y", "@cocal/google-calendar-mcp"]`)
- `SATARK_CALENDAR_MCP_TOOL_CREATE_EVENT` (force a specific MCP tool name)

Optional MCP sync for productivity workflows:

- `SATARK_NOTES_MCP_COMMAND` and `SATARK_NOTES_MCP_ARGS` (JSON list)
- `SATARK_TASKS_MCP_COMMAND` and `SATARK_TASKS_MCP_ARGS` (JSON list)
- Optional tool overrides: `SATARK_NOTES_MCP_TOOL`, `SATARK_TASKS_MCP_TOOL`

Quick setup:

```bash
cp .env.example .env
# edit .env and fill required values
python scripts/check_mcp_env.py
```

If you use refresh-token mode, ensure your one-time consent flow includes both scopes:

- https://www.googleapis.com/auth/calendar.events
- https://www.googleapis.com/auth/gmail.compose

## Firestore Vector Search Setup (Real)

SATARK uses Firestore vector indexes against the fraud_patterns collection with embeddings generated from text-embedding-005.

1. Seed and backfill vectors:

```bash
python scripts/seed_fraud_patterns.py
python scripts/backfill_pattern_embeddings.py
```

2. Create required vector indexes:

```bash
gcloud firestore indexes composite create \
  --project=satark-ai-492219 \
  --collection-group=fraud_patterns \
  --query-scope=COLLECTION \
  --field-config=order=ASCENDING,field-path=active \
  --field-config=order=ASCENDING,field-path=scam_type \
  --field-config=vector-config='{"dimension":"768","flat": "{}"}',field-path=embedding

gcloud firestore indexes composite create \
  --project=satark-ai-492219 \
  --collection-group=fraud_patterns \
  --query-scope=COLLECTION \
  --field-config=order=ASCENDING,field-path=active \
  --field-config=vector-config='{"dimension":"768","flat": "{}"}',field-path=embedding
```

3. Verify indexes are ready:

```bash
gcloud firestore indexes composite list --project=satark-ai-492219
```

## 60-Second Judge Demo Script

1. Type mode
- Paste a realistic UPI or OTP scam message.
- Click Analyze and show scam type, confidence, risk level, actions, and case reference.

2. Live mode
- Click Live and speak a fake bank-call script.
- Show streaming risk updates and immediate victim guidance.

3. Outcome framing
- Highlight golden-hour urgency and direct complaint escalation path (1930 and cybercrime.gov.in).

## Evaluation Mapping

| Evaluation Criterion | SATARK AI Evidence |
| --- | --- |
| Working demo | End-to-end input to action flow with live and file-based analysis |
| Architecture | Manager + specialist agents with parallel orchestration and A2A envelope metadata |
| Google-native usage | Vertex AI, GenAI SDK, ADK components, cloud-first deployment path |
| Innovation | Citizen-first automation of multi-step fraud triage and response |
| Execution | Clean modular Python backend, practical API surface, deployable web UI |

## Repository Structure

```text
satark-ai/
  agents/
    apk_analyzer/
    audio_analyzer/
    golden_hour/
    manager/
    osint/
    scam_detector/
  api/
  artifacts/
  benchmarks/
  db/
  docs/
  frontend/
  satark_mcp/
  scripts/
    regression/
  tests/
  tools/
  config.py
  Dockerfile
  .env.example
  requirements.txt
```

## Disclaimer

SATARK AI is a decision-support and response-acceleration system. It does not replace official law-enforcement authority or legal process. Victims should always report incidents through official channels.
