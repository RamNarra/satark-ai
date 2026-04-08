# MASTER REPO AUDIT

Date: 2026-04-08
Repository: satark-ai
Audit mode: forensic architecture and behavior reconstruction

## 1) Executive Truth

SATARK AI contains real multi-agent fraud-analysis and productivity-workflow implementations, but the currently served citizen flows are strongly triage and latency biased.

The most important runtime truth for the demo is this:
- Default analyze requests are normalized to triage mode in the backend, regardless of what clients request.
- Served frontends also default to fast-first triage flags and usually disable deep analysis, report generation, and MCP actions.
- Deep analysis exists and is contract-safe, but requires explicit trigger.
- MCP and Google actions exist, but are gated by manager decisions and OAuth/env configuration.

Bottom line:
- Core architecture exists and is credible.
- Default UX path can under-show that architecture unless demo flow intentionally triggers deep and MCP branches.

## 2) Scope And Method

This audit covered API, orchestrators, agents, MCP wrappers, Google integration, persistence layer, frontend contracts, tests, and git archaeology.

Evidence style:
- File path + line anchors for every critical claim.
- Verified facts only; assumptions are explicitly labeled.

## 3) Reconstructed Runtime Architecture

### 3.1 API And Route Surfaces

Primary app and routing:
- FastAPI app boot: api/main.py:238
- Workflow router mounted into main app: api/main.py:242
- Static asset mount: api/main.py:244
- Served UI chooser for /ui: api/main.py:246
- Ops board route /ops: api/main.py:254
- Root route chooser /: api/main.py:259

Fraud analysis API surface:
- Warmup status: api/main.py:4259
- Analyze preprocess: api/main.py:4270
- Triage analyze: api/main.py:4281
- Deep analyze trigger: api/main.py:4339
- SSE stream: api/main.py:4411
- Result polling: api/main.py:4455

Legacy still-present fraud surface:
- Legacy unified analyze endpoint: api/main.py:4676
- Legacy mode-specific endpoints remain under /analyze/*: api/main.py:4757, api/main.py:4773, api/main.py:4801, api/main.py:4829
- Live websocket stream route: api/main.py:4861

Productivity workflow API surface:
- Workflow run: api/workflow_api.py:210
- Chat to workflow alias: api/workflow_api.py:215
- Workflow get: api/workflow_api.py:225
- Workflow stream: api/workflow_api.py:268
- Session snapshot: api/workflow_api.py:317
- Artifact approval: api/workflow_api.py:331

### 3.2 Fraud Pipeline (Manager-First)

Main API imports and fallback chain:
- Primary manager pipeline import from agents.manager package: api/main.py:34
- Package export points to ADK manager when available: agents/manager/__init__.py:2
- Legacy fallback function imported separately: api/main.py:35
- Legacy fallback path invoked on timeout/degrade/error: api/main.py:3697, api/main.py:3772, api/main.py:3809, api/main.py:3845

Fraud manager orchestration in ADK manager:
- Pipeline entrypoint: agents/manager/adk_manager.py:141
- Detection then optional OSINT and golden-hour tasks in parallel: agents/manager/adk_manager.py:293, agents/manager/adk_manager.py:327, agents/manager/adk_manager.py:338
- Final manager decision contract generation and sanitization: agents/manager/adk_manager.py:421, agents/manager/adk_manager.py:2023, agents/manager/adk_manager.py:2028
- MCP plan normalization and gating: agents/manager/adk_manager.py:433, agents/manager/adk_manager.py:1397
- Preventive-only suppression of MCP escalation: agents/manager/adk_manager.py:1670

### 3.3 Productivity Workflow Pipeline

Productivity orchestrator exists and persists workflow artifacts:
- Orchestrator entrypoint: agents/manager/orchestrator.py:55
- Plan includes memory, notes, tasks, research, schedule agents: agents/manager/orchestrator.py:40
- Parallel notes and task execution: agents/manager/orchestrator.py:106
- Persistence writes to notes/tasks/events/artifacts repos: agents/manager/orchestrator.py:125, agents/manager/orchestrator.py:126, agents/manager/orchestrator.py:127, agents/manager/orchestrator.py:146
- Optional MCP sync branch for calendar/tasks/notes: agents/manager/orchestrator.py:150, agents/manager/orchestrator.py:151, agents/manager/orchestrator.py:152

Runtime entry from API:
- Workflow API invokes run_productivity_workflow: api/workflow_api.py:11, api/workflow_api.py:143

### 3.4 Storage Model And Persistence

In-memory run state (process scoped):
- RUN_STORE declaration: api/main.py:745

Fraud run persistence and result fallback:
- Save case on async orchestrated completion: api/main.py:4158
- Save case on legacy sync path: api/main.py:4662
- Result fallback loader: api/main.py:2497
- /api/result fallback to persisted case if run_id not in memory: api/main.py:4459

Firestore-backed repositories:
- Firestore client creation: db/client.py:10, db/client.py:14
- Generic write/read/query wrappers: db/firestore.py:15, db/firestore.py:26, db/firestore.py:41
- Fraud collections and vector retrieval: db/operations.py:23, db/operations.py:24, db/operations.py:25, db/operations.py:26, db/operations.py:130, db/operations.py:162
- Workflow/session/task/note/event/artifact/memory collections: db/sessions_repo.py:5, db/workflows_repo.py:7, db/tasks_repo.py:8, db/notes_repo.py:8, db/events_repo.py:8, db/artifacts_repo.py:8, db/memories_repo.py:7

## 4) Contract Behavior Findings (Two-Phase)

Contract versioning:
- Contract constants: api/main.py:77, api/main.py:78

Triage enforcement in /api/analyze:
- Triage contract normalizer: api/main.py:1737
- Forced options deep_analysis=false, fast_first=true, generate_report=false, trigger_mcp_actions=false: api/main.py:1742, api/main.py:1743, api/main.py:1744, api/main.py:1745

Deep trigger path in /api/analyze/deep:
- Deep payload builder enables deep mode and explicit report/MCP options: api/main.py:3332, api/main.py:3338, api/main.py:3339, api/main.py:3340, api/main.py:3341
- Deep source run constraints and idempotent replay logic: api/main.py:4341, api/main.py:4349, api/main.py:4358, api/main.py:4362, api/main.py:3372

Fast-first and short-circuit behavior:
- fast_first env default resolver: api/main.py:1722, api/main.py:1723
- Fast-path selector in orchestrator: api/main.py:3545
- used_fast_path short-circuit completion branch: api/main.py:3868
- Explicit fast-path status in tool result: api/main.py:3864

Clarification follow-up hydration and guardrails:
- Follow-up hydration from prior session evidence: api/main.py:1485
- Clarification follow-up fast-path reuse reason: api/main.py:3830

Result metadata contract:
- Result document assembly with stage/deep eligibility metadata: api/main.py:2657, api/main.py:3212, api/main.py:3214, api/main.py:3216, api/main.py:3218

Regression tests align to this behavior:
- Contract test suite: tests/test_two_phase_contract.py:9
- Asserts triage normalization in /api/analyze: tests/test_two_phase_contract.py:55, tests/test_two_phase_contract.py:68, tests/test_two_phase_contract.py:69, tests/test_two_phase_contract.py:70, tests/test_two_phase_contract.py:71
- Asserts deep path options in /api/analyze/deep: tests/test_two_phase_contract.py:78, tests/test_two_phase_contract.py:104, tests/test_two_phase_contract.py:105, tests/test_two_phase_contract.py:106, tests/test_two_phase_contract.py:107

## 5) Frontend To Backend Contract Alignment

What is currently served:
- /ui serves satark-ui-v2 when present: api/main.py:246, api/main.py:248
- / serves satark-ui-v2 when present: api/main.py:259, api/main.py:261
- /ops serves ops board index.html: api/main.py:254, api/main.py:256

Citizen chat shell (satark-ui-v2) behavior:
- Calls /api/analyze: frontend/satark-ui-v2.html:2632
- Default options set triage and disable report/deep/MCP: frontend/satark-ui-v2.html:2622, frontend/satark-ui-v2.html:2623, frontend/satark-ui-v2.html:2624, frontend/satark-ui-v2.html:2625
- Clarification follow-up also sends triage defaults: frontend/satark-ui-v2.html:2466, frontend/satark-ui-v2.html:2467, frontend/satark-ui-v2.html:2468, frontend/satark-ui-v2.html:2469, frontend/satark-ui-v2.html:2470
- Explicit deep trigger exists and calls /api/analyze/deep: frontend/satark-ui-v2.html:1391

Citizen classic UI script behavior:
- Calls /api/analyze with same triage-biased defaults: frontend/ui.js:639, frontend/ui.js:632, frontend/ui.js:633, frontend/ui.js:634, frontend/ui.js:635

Ops board behavior:
- Calls /api/analyze with same triage-biased defaults: frontend/app.js:330, frontend/app.js:343, frontend/app.js:344, frontend/app.js:345, frontend/app.js:346

Legacy UI drift still present:
- Legacy satark-ui.html still posts to /analyze (legacy route): frontend/satark-ui.html:853
- Transitional satark-ui (1).html uses /api/analyze with generate_report true and no MCP: frontend/satark-ui (1).html:952, frontend/satark-ui (1).html:949

## 6) Google And MCP Integration Truth

Google OAuth web flow exists:
- Start/callback/auth-status/logout routes: api/main.py:451, api/main.py:514, api/main.py:641, api/main.py:679
- OAuth persistence in session record: api/main.py:622, db/sessions_repo.py:32, db/sessions_repo.py:44
- Calendar MCP token path persisted on callback when available: api/main.py:588, api/main.py:590

Workspace action utilities exist:
- Google credential builder: tools/google_workspace.py:26
- Tasks creator: tools/google_workspace.py:79
- Case report doc creator: tools/google_workspace.py:131
- Gmail draft creator: tools/google_workspace.py:180

MCP wrappers are real but env-gated:
- Runtime session manager wrapper: satark_mcp/runtime.py:77
- Calendar MCP default package via npx @cocal/google-calendar-mcp: satark_mcp/calendar_client.py:99, satark_mcp/calendar_client.py:100
- Calendar auth requirements and not_configured branch: satark_mcp/calendar_client.py:105, satark_mcp/calendar_client.py:114, satark_mcp/calendar_client.py:117
- Tasks MCP not_configured branch: satark_mcp/tasks_client.py:41
- Notes MCP not_configured branch: satark_mcp/notes_client.py:41

## 7) Git Archaeology And Pivot Timeline

Recent pivot chain from commit history:
- 86d65cb: productivity workflow experience introduced (new workflow APIs, repos, MCP wrappers).
- a29b8c8: repivot to fraud-first UI and report contract.
- dab815a: manager-first no-harm contract hardening.
- caf8b41: citizen chat shell replacement and calm-vs-urgent regression lock.
- 2ba8c88: preserve manager chat_reply and render it first in UI.

Current workspace state is heavily dirty and includes many runtime evidence artifacts plus untracked additions (git status snapshot captured during audit).

## 8) Requirement Compliance Matrix

| Requirement | Status | Evidence | Notes |
|---|---|---|---|
| Real multi-agent fraud orchestration | Verified | agents/manager/adk_manager.py:141, agents/manager/adk_manager.py:338 | Detection plus parallel OSINT/golden-hour with manager contract. |
| Real multi-agent productivity orchestration | Verified but isolated | agents/manager/orchestrator.py:55, api/workflow_api.py:210 | Exists but not used by served citizen/ops frontends. |
| Deep analysis phase is explicit and safe | Verified | api/main.py:4339, api/main.py:4349, api/main.py:4362 | Deep source validation + idempotent replay present. |
| Triage-first contract enforced | Verified | api/main.py:1737, api/main.py:1742 | Backend overrides incoming options in /api/analyze. |
| MCP invocation path exists | Verified but gated | agents/manager/adk_manager.py:432, agents/manager/adk_manager.py:452 | Requires manager decision + OAuth/env readiness. |
| Google OAuth integration exists | Verified | api/main.py:451, api/main.py:514, api/main.py:622 | Session-backed token persistence implemented. |
| Firestore persistence exists | Verified | api/main.py:4158, db/client.py:14, db/operations.py:69 | Run persistence + collection repos implemented. |
| Frontend exposes deep/MCP by default | Not verified | frontend/satark-ui-v2.html:2622, frontend/satark-ui-v2.html:2625 | Defaults currently suppress deep/report/MCP except explicit deep trigger function. |
| Legacy drift removed | Not verified | api/main.py:4676, frontend/satark-ui.html:853 | Legacy endpoint and legacy UI call path still present. |

## 9) Findings Ordered By Severity

### Critical 1: Demo path under-shows core architecture by default

Problem:
- Served frontends default to triage-only fast-first options and disable deep/report/MCP actions.
- Backend also enforces triage defaults in /api/analyze.

Impact:
- Judges may only see fast triage responses and conclude there is no real deep orchestration or MCP behavior.

Evidence:
- frontend/satark-ui-v2.html:2622, frontend/satark-ui-v2.html:2623, frontend/satark-ui-v2.html:2624, frontend/satark-ui-v2.html:2625
- frontend/ui.js:632, frontend/ui.js:633, frontend/ui.js:634, frontend/ui.js:635
- frontend/app.js:343, frontend/app.js:344, frontend/app.js:345, frontend/app.js:346
- api/main.py:1737, api/main.py:1742, api/main.py:1743, api/main.py:1744, api/main.py:1745

### High 2: Architecture drift between fraud and productivity stories

Problem:
- Productivity workflow stack is implemented and exposed via API, but active frontends call fraud /api/analyze flows, not workflow APIs.

Impact:
- Demo narrative can become inconsistent if team claims one system while UI exercises another.

Evidence:
- workflow routes: api/workflow_api.py:210, api/workflow_api.py:215
- workflow engine: agents/manager/orchestrator.py:55
- frontends call /api/analyze: frontend/satark-ui-v2.html:2632, frontend/ui.js:639, frontend/app.js:330

### High 3: Legacy path still present and can confuse verification

Problem:
- Legacy /analyze routes remain active; legacy UI still posts there.

Impact:
- Side-by-side behavior differences may appear random during demo prep if wrong page is used.

Evidence:
- legacy endpoint: api/main.py:4676
- legacy UI call: frontend/satark-ui.html:853

### High 4: APK analyzer has unreachable block in legacy module

Problem:
- In agents/apk_analyzer/agent.py, code after early return under if not apk_bytes is indented beneath that return and unreachable.

Impact:
- Legacy APK branch behavior can diverge unexpectedly and is brittle for fallback demonstrations.

Evidence:
- agents/apk_analyzer/agent.py:321, agents/apk_analyzer/agent.py:322, agents/apk_analyzer/agent.py:324

### Medium 5: Environment readiness not guaranteed in current shell

Problem:
- Contract test execution failed due missing FastAPI dependency in active interpreter.

Impact:
- Local proof runs can fail in demo prep unless environment is standardized before execution.

Evidence:
- unittest attempt returned ModuleNotFoundError: fastapi (observed during this audit run)
- required dependency listed: requirements.txt:14

## 10) Verified Vs Assumed

Verified in code:
- Multi-agent fraud path, deep phase mechanics, OAuth and MCP adapters, Firestore persistence.

Not auto-verified in this pass:
- Live MCP execution success with real credentials in this current shell.
- End-to-end productivity workflow invoked from any currently served UI.

## 11) Final Assessment

The repository is not fake or hollow. It contains substantial architecture and multiple real pipelines.

The main risk is demonstration alignment, not missing code:
- If you run default citizen/ops flows without intentional deep and MCP triggers, the demo can look shallow.
- If you steer flows through explicit deep run and OAuth-backed MCP branches, the underlying architecture is strong enough to defend under technical questioning.
