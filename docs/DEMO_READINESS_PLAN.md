# DEMO READINESS PLAN

Date: 2026-04-08
Target: hackathon-safe live demo with deterministic behavior

## 1) Demo Objective

Demonstrate SATARK AI as a real, two-phase anti-scam system with optional actionability (reports, MCP/Google workflows), while avoiding accidental fallback to shallow-only behavior.

## 2) Go / No-Go Gates

All gates below should be GREEN before going live.

### Gate A: Runtime boot and route sanity

Pass criteria:
- API starts without import/runtime errors.
- Served UI route is expected page.
- Warmup endpoint responds healthy.

Checks:
1. Start backend and confirm app boots from api/main.py.
2. Open /ui and confirm satark-ui-v2 shell is served (api/main.py:246, api/main.py:248).
3. Validate /api/warmup/status responds (api/main.py:4259).

No-Go if:
- /ui serves unexpected legacy shell.
- warmup remains error state.

### Gate B: Triage contract determinism

Pass criteria:
- /api/analyze request is normalized to triage contract.
- Response includes expected stage metadata and no deep side effects.

Checks:
1. Send a normal user message through UI and verify request path is /api/analyze (frontend/satark-ui-v2.html:2632).
2. Confirm options are triage defaults in payload: deep false, fast_first true, generate_report false, trigger_mcp_actions false (frontend/satark-ui-v2.html:2622-2625).
3. Confirm backend enforces same normalization (api/main.py:1737, api/main.py:1742-1745).

No-Go if:
- triage request unexpectedly runs deep by default.
- result metadata is inconsistent with stage=triage semantics.

### Gate C: Deep-run acceptance and replay safety

Pass criteria:
- /api/analyze/deep only accepts valid source run IDs and is idempotent.

Checks:
1. Trigger deep from UI explicit action and verify endpoint /api/analyze/deep is used (frontend/satark-ui-v2.html:1391).
2. Verify backend enforces source_run_id constraints (api/main.py:4341, api/main.py:4349).
3. Re-submit same source and verify idempotent replay behavior (api/main.py:4362).

No-Go if:
- deep trigger bypasses source validation.
- duplicate deep requests generate conflicting run state.

### Gate D: Stream and result retrieval

Pass criteria:
- SSE stream and polling both work for active run IDs.
- Persisted result fallback works when in-memory state is absent.

Checks:
1. Verify /api/stream/{run_id} emits events (api/main.py:4411).
2. Verify /api/result/{run_id} returns final/partial status (api/main.py:4455).
3. Simulate memory miss and ensure persisted fallback retrieval path is active (api/main.py:4459, api/main.py:2497).

No-Go if:
- stream starves with no terminal state.
- completed runs cannot be recovered from persistence.

### Gate E: OAuth and MCP readiness (optional but recommended)

Pass criteria:
- OAuth start/callback/status/logout endpoints functional.
- Session auth indicates connected state when expected.
- MCP tools report configured, not not_configured.

Checks:
1. Execute OAuth handshake: /auth/google/start, /auth/google/callback (api/main.py:451, api/main.py:514).
2. Confirm auth status route returns connected user state /api/auth/status (api/main.py:641).
3. Ensure callback persisted OAuth payload into session (api/main.py:622, db/sessions_repo.py:32).
4. Dry-run MCP tools and verify no not_configured responses from clients (satark_mcp/calendar_client.py:114, satark_mcp/tasks_client.py:41, satark_mcp/notes_client.py:41).

No-Go if:
- OAuth status remains disconnected for expected account.
- MCP clients return not_configured in the planned demo path.

### Gate F: Regression confidence

Pass criteria:
- Two-phase contract tests pass in the selected runtime.

Checks:
1. Install dependencies from requirements.txt.
2. Run python -m unittest tests.test_two_phase_contract -v.

Current known issue:
- In this audit shell, test execution failed with ModuleNotFoundError: fastapi, indicating environment mismatch against requirements.txt:14.

No-Go if:
- Contract tests fail after environment has been correctly provisioned.

## 3) Pre-Demo Checklist (Operator)

Use this as T-60 to T-10 checklist.

1. Environment
- Activate correct Python environment.
- Install exact dependencies from requirements.txt.
- Export required env vars from .env/.env.example.

2. Data and storage
- Confirm Firestore project credentials are present if persistence is required.
- Confirm collection write permissions are valid.

3. Backend
- Start API process.
- Verify /api/warmup/status and /api/preprocess.

4. Frontend
- Open /ui and ensure v2 shell is loaded, not legacy UI.
- Keep /ops hidden unless specifically needed for operator view.

5. OAuth + MCP (if part of script)
- Complete Google OAuth before live segment.
- Confirm /api/auth/status is connected.
- Perform one dry-run MCP tool call.

6. Demo fixtures
- Prepare at least one prevented-scam triage input.
- Prepare one deep-escalation input that triggers deep run.
- Prepare one follow-up clarification question to show context carryover.

## 4) Recommended Demo Script (Deterministic)

### Sequence 1: Fast triage value (30-60s)

Goal:
- Show immediate guardrail response with confidence and actionable brief.

Flow:
1. Submit suspicious message in /ui.
2. Show quick risk assessment return via /api/analyze path.
3. Highlight that this is triage phase by design.

### Sequence 2: Deep escalation (60-120s)

Goal:
- Prove non-trivial second phase and replay-safe behavior.

Flow:
1. Click deep analysis trigger in UI.
2. Confirm new run uses /api/analyze/deep.
3. Show richer evidence and stronger recommendation payload.

### Sequence 3: Actionability (optional 60-90s)

Goal:
- Show integration capability, not just classification.

Flow:
1. If OAuth is connected, trigger an allowed MCP action route.
2. Show resulting artifact status and persisted run evidence.

## 5) Fallback Strategy (When Live Fails)

### Fallback A: OAuth/MCP unavailable

Use:
- Continue with triage + deep demonstration only.

Narrative:
- "Action integrations are available but gated by live account authorization in this environment. We can still demonstrate full two-phase analysis and incident guidance safely."

### Fallback B: External dependency latency

Use:
- Demonstrate persisted evidence from artifacts/runtime-evidence and /api/result polling behavior.

Narrative:
- "The pipeline is asynchronous by design; while stream catches up, we can inspect already persisted run outputs and contract metadata."

### Fallback C: Legacy route confusion

Use:
- Pin to /ui route only and avoid legacy HTML files.

Narrative:
- "We are using the current citizen shell that targets the contract-safe API surface."

## 6) Demo Anti-Patterns To Avoid

1. Do not open legacy satark-ui.html during demo (frontend/satark-ui.html:853 uses legacy /analyze path).
2. Do not claim deep analysis happened if only /api/analyze was used.
3. Do not claim MCP actionability if auth status is disconnected.
4. Do not rely on ad-hoc environment setup minutes before going live.

## 7) Definition Of Demo-Ready

Demo-ready means all of the following are true:
1. /ui serves expected shell.
2. Triage run executes and returns deterministic contract output.
3. Deep run executes from valid source and shows second-phase behavior.
4. Stream and result endpoints both recover run state.
5. Contract tests pass in the selected runtime.
6. If MCP is in narrative, OAuth status is connected and dry-run action succeeds.

## 8) Ownership And Timing

Suggested assignment:
1. Engineer A: environment and backend startup gate.
2. Engineer B: OAuth/MCP gate and fallback prep.
3. Presenter: script rehearsal and timing.

Suggested timeline:
1. T-60: gates A/B/C.
2. T-45: gates D/E.
3. T-30: gate F.
4. T-20: full scripted dry run.
5. T-10: backup browser tab and fallback artifacts ready.
