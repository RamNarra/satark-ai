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
- Pattern intelligence matching and case persistence hooks.
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

- GET /health
- GET /stats
- GET /ui
- POST /analyze
- POST /analyze/text
- POST /analyze/image
- POST /analyze/audio
- POST /analyze/apk
- WS /stream

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

## Environment Variables

Minimum recommended:

- GOOGLE_CLOUD_PROJECT
- GOOGLE_CLOUD_LOCATION
- GOOGLE_APPLICATION_CREDENTIALS (or equivalent ADC path)
- GEMINI_API_KEY (only for components running API-key mode)
- GOOGLE_CALENDAR_ID (optional, defaults to primary)
- SATARK_CALENDAR_TIMEZONE (optional, defaults to Asia/Kolkata)

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
  db/
  frontend/
  tools/
  config.py
  requirements.txt
```

## Disclaimer

SATARK AI is a decision-support and response-acceleration system. It does not replace official law-enforcement authority or legal process. Victims should always report incidents through official channels.
