# FILE INDEX AND ENTRYPOINTS

Date: 2026-04-08
Purpose: one-stop map of executable entrypoints, routed surfaces, and key module ownership.

## 1) Top-Level Runtime Entry

Primary backend app:
- api/main.py: FastAPI app declaration and startup wiring (api/main.py:238).

Workflow slice mounted into primary app:
- api/workflow_api.py router included in main app (api/main.py:242).

Frontend serving roots:
- /ui route chooser (api/main.py:246)
- /ops route (api/main.py:254)
- / root chooser (api/main.py:259)

## 2) API Endpoint Index

### 2.1 Fraud Analysis (Current Contract Surface)

- GET /api/warmup/status -> api/main.py:4259
- POST /api/preprocess -> api/main.py:4270
- POST /api/analyze -> api/main.py:4281
- POST /api/analyze/deep -> api/main.py:4339
- GET /api/stream/{run_id} -> api/main.py:4411
- GET /api/result/{run_id} -> api/main.py:4455

Supporting internals for this surface:
- Triage normalizer: _enforce_triage_request_contract(api/main.py:1737)
- Async orchestrator: _orchestrate_analysis_run(api/main.py:3405)
- Run persistence helper: _persist_run_to_firestore(api/main.py:2526)

### 2.2 Auth / Google

- GET /auth/google/start -> api/main.py:451
- GET /auth/google/callback -> api/main.py:514
- GET /api/auth/status -> api/main.py:641
- POST /auth/google/logout -> api/main.py:679

Auth persistence bridge:
- set_google_oauth call site: api/main.py:622
- session repo mutation: db/sessions_repo.py:32

### 2.3 Legacy Analysis Surface (Still Active)

- POST /analyze -> api/main.py:4676
- POST /analyze/text -> api/main.py:4757
- POST /analyze/audio -> api/main.py:4773
- POST /analyze/image -> api/main.py:4801
- POST /analyze/apk -> api/main.py:4829
- WebSocket /stream/{job_id} -> api/main.py:4861

## 3) Workflow API Endpoint Index

Defined in api/workflow_api.py:
- POST /workflow/run -> api/workflow_api.py:210
- POST /chat -> api/workflow_api.py:215
- GET /workflow/{workflow_id} -> api/workflow_api.py:225
- GET /workflow/{workflow_id}/stream -> api/workflow_api.py:268
- GET /sessions/{session_id} -> api/workflow_api.py:317
- POST /artifacts/{artifact_id}/approve -> api/workflow_api.py:331

Primary workflow orchestrator call site:
- run_productivity_workflow import and invocation: api/workflow_api.py:11, api/workflow_api.py:143

## 4) Orchestrator And Agent Entry Map

### 4.1 Fraud Manager Stack

Entrypoints:
- run_pipeline in ADK manager: agents/manager/adk_manager.py:141
- manager package export that main imports: agents/manager/__init__.py:2

Major stages:
- Scam detection: agents/manager/adk_manager.py:293
- Parallel evidence gather: agents/manager/adk_manager.py:338
- Manager decision synthesis: agents/manager/adk_manager.py:421
- MCP plan normalization: agents/manager/adk_manager.py:1397

Downstream fraud sub-agents called by manager:
- scam_detector: agents/scam_detector/agent.py
- osint: agents/osint/agent.py
- golden_hour: agents/golden_hour/agent.py
- research_agent and notes/memory/task/schedule agents as applicable by mode.

### 4.2 Productivity Orchestrator Stack

Entrypoint:
- run_productivity_workflow: agents/manager/orchestrator.py:55

Major stages:
- plan creation: agents/manager/orchestrator.py:95
- parallel notes/task gather: agents/manager/orchestrator.py:106
- repo persistence writes: agents/manager/orchestrator.py:125-127, 146
- optional MCP sync: agents/manager/orchestrator.py:150-152

## 5) Frontend Entry Map

### 5.1 Served By Default

- frontend/satark-ui-v2.html: default citizen shell selected by /ui and / when file exists (api/main.py:248, api/main.py:261).
- frontend/index.html: served by /ops route (api/main.py:256).

### 5.2 Request Path Contracts

satark-ui-v2:
- analyze call /api/analyze: frontend/satark-ui-v2.html:2632
- deep call /api/analyze/deep: frontend/satark-ui-v2.html:1391
- triage default payload flags: frontend/satark-ui-v2.html:2622-2625

ui.js (classic citizen script):
- analyze call /api/analyze: frontend/ui.js:639
- triage-biased options: frontend/ui.js:632-635

ops app.js:
- analyze call /api/analyze: frontend/app.js:330
- triage-biased options: frontend/app.js:343-346

legacy shell still in repo:
- frontend/satark-ui.html posts to /analyze: frontend/satark-ui.html:853

## 6) Persistence And Data Access Map

Core persistence modules:
- db/client.py: Firestore client singleton and project selection.
- db/firestore.py: low-level collection operations.
- db/operations.py: fraud case/history pattern APIs.

Domain repositories:
- db/sessions_repo.py
- db/workflows_repo.py
- db/tasks_repo.py
- db/notes_repo.py
- db/events_repo.py
- db/artifacts_repo.py
- db/memories_repo.py

Key write/read anchors:
- Save fraud case: db/operations.py:69
- Get fraud case by run_id: db/operations.py:112
- Save session OAuth context: db/sessions_repo.py:32

## 7) MCP And External Action Entry Map

MCP runtime core:
- satark_mcp/runtime.py: MCPServerSession manager and call_tool wrapper.

Tool clients:
- satark_mcp/calendar_client.py
- satark_mcp/tasks_client.py
- satark_mcp/notes_client.py

Registry factory:
- satark_mcp/registry.py: get_clients helper.

Not-configured guard anchors:
- calendar auth/env gating: satark_mcp/calendar_client.py:114
- tasks not configured return: satark_mcp/tasks_client.py:41
- notes not configured return: satark_mcp/notes_client.py:41

Google direct utility tools (non-MCP wrappers):
- tools/google_workspace.py: create_google_tasks(79), create_case_report(131), create_gmail_draft(180)

## 8) Script And Test Entrypoints

Tests:
- tests/test_two_phase_contract.py: verifies triage normalization and deep payload contracts.

Regression scripts:
- scripts/regression/* (artifactized runtime evidence generators and comparators).

Utility scripts:
- scripts/check_mcp_env.py: environment diagnostics for MCP setup.
- scripts/seed_fraud_patterns.py: seed embeddings/pattern corpus.

## 9) Deployment / Runtime Packaging Entry Map

Dependencies and environment:
- requirements.txt
- config.py
- .env.example

Containerization:
- Dockerfile

Readme runbook:
- README.md

## 10) Fast Lookup: Who Handles What

- "Why did triage override my options?" -> api/main.py:1737-1745
- "Where is deep analysis triggered?" -> api/main.py:4339 and frontend/satark-ui-v2.html:1391
- "Where is manager decision built?" -> agents/manager/adk_manager.py:421, 2023
- "Where are results persisted?" -> api/main.py:4158 and db/operations.py:69
- "Why MCP says not configured?" -> satark_mcp/calendar_client.py:114, satark_mcp/tasks_client.py:41, satark_mcp/notes_client.py:41
- "Which UI is actually served?" -> api/main.py:246-261
- "Why are there legacy behavior differences?" -> api/main.py:4676 and frontend/satark-ui.html:853
