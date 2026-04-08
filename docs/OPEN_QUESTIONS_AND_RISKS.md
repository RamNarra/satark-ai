# OPEN QUESTIONS AND RISKS

Date: 2026-04-08
Purpose: unresolved decisions, blockers, and mitigation ownership before demo and handoff.

## 1) Open Questions

### Q1. Which product story is primary for the demo: fraud pipeline or productivity workflow?

Context:
- Fraud routes are what current served frontends call (/api/analyze).
- Productivity workflow is a separate API/orchestrator stack.

Evidence:
- Fraud calls from served UIs: frontend/satark-ui-v2.html:2632, frontend/ui.js:639, frontend/app.js:330
- Workflow surface exists separately: api/workflow_api.py:210, agents/manager/orchestrator.py:55

Decision needed:
- Pick one primary narrative for stage demo and keep supporting slides/code paths aligned.

Owner:
- Product lead + presenter.

Deadline:
- Before final rehearsal.

### Q2. Should triage defaults remain hard-enforced in /api/analyze for demo mode?

Context:
- Backend currently force-normalizes triage options in /api/analyze.
- UI payloads already default to those values.

Evidence:
- api/main.py:1737, api/main.py:1742-1745
- frontend/satark-ui-v2.html:2622-2625

Decision needed:
- Keep strict triage enforcement (safer, faster) or allow a "show full" toggle at API/UI level for demo richness.

Owner:
- Backend lead.

Deadline:
- Before feature freeze for demo branch.

### Q3. Should legacy /analyze routes stay active during the hackathon demo window?

Context:
- Legacy endpoints and legacy UI are still present.

Evidence:
- api/main.py:4676
- frontend/satark-ui.html:853

Decision needed:
- Keep for backward compatibility or hide/disable for demo determinism.

Owner:
- Tech lead.

Deadline:
- Before rehearsal runbook finalization.

### Q4. Is MCP actionability a required judging criterion or optional bonus?

Context:
- MCP clients are env/auth-gated and can return not_configured.

Evidence:
- satark_mcp/calendar_client.py:114
- satark_mcp/tasks_client.py:41
- satark_mcp/notes_client.py:41

Decision needed:
- Decide if OAuth+MCP setup is mandatory on stage or shown only if gate passes.

Owner:
- Presenter + integrations engineer.

Deadline:
- T-24h.

### Q5. Which interpreter/environment is canonical for local test execution?

Context:
- Contract tests failed in this audit shell due missing fastapi dependency.

Evidence:
- requirements.txt:14 includes fastapi
- observed test error: ModuleNotFoundError: fastapi during python -m unittest tests.test_two_phase_contract -v

Decision needed:
- Define and document one canonical local environment bootstrap command sequence.

Owner:
- DevOps/runtime owner.

Deadline:
- Immediate.

## 2) Risk Register (Prioritized)

| ID | Risk | Severity | Likelihood | Evidence | Mitigation | Owner | Target Date |
|---|---|---|---|---|---|---|---|
| R1 | Demo appears shallow because default path is triage-only fast-first | Critical | High | api/main.py:1737-1745, frontend/satark-ui-v2.html:2622-2625 | Script explicit two-phase flow including /api/analyze/deep; rehearse transition narration | Presenter | T-1 day |
| R2 | Narrative drift between fraud and productivity architectures | High | Medium | api/workflow_api.py:210 vs frontend/satark-ui-v2.html:2632 | Pick primary story and align slides + route usage | Product lead | T-2 days |
| R3 | Legacy endpoint/UI accidentally used on stage | High | Medium | api/main.py:4676, frontend/satark-ui.html:853 | Pin demo URL to /ui; optionally hide legacy assets in demo branch | Tech lead | T-1 day |
| R4 | OAuth/MCP unavailable in venue environment | High | Medium | api/main.py:451, api/main.py:514, satark_mcp/calendar_client.py:114 | Complete OAuth pre-stage; keep non-MCP fallback script and artifacts | Integrations engineer | T-1 day |
| R5 | Local regression checks not reproducible due env mismatch | Medium | High | requirements.txt:14 + observed missing fastapi at runtime | Publish canonical setup script and lock interpreter in docs | DevOps/runtime owner | Immediate |
| R6 | Fast-path short-circuit can skip deeper pipeline unexpectedly | Medium | Medium | api/main.py:3545, api/main.py:3868 | Use fixtures known to produce deep eligibility; verify with pre-demo dry run | Backend lead | T-1 day |
| R7 | Clarification follow-up behavior may be misinterpreted as full rerun | Medium | Medium | api/main.py:3830 | Explain follow-up hydration semantics during demo and in docs | Presenter | T-1 day |
| R8 | APK legacy module unreachable block may surface in fallback testing | Medium | Low | agents/apk_analyzer/agent.py:321-324 | Patch unreachable block or avoid legacy APK fallback in demo script | Security/agent owner | T-2 days |
| R9 | Dirty workspace may introduce accidental behavior changes | Medium | Medium | audit-time git status showed extensive modified/untracked files | Cut clean demo branch and cherry-pick approved commits only | Tech lead | Immediate |

## 3) Blockers

### B1. Canonical environment not yet locked for test execution

Impact:
- Cannot rely on last-minute confidence checks.

Unblock actions:
1. Define exact Python version and venv/conda commands.
2. Reinstall dependencies from requirements.txt.
3. Re-run tests/test_two_phase_contract.py.

### B2. Demo decision on MCP requirement not finalized

Impact:
- Stage script and fallback deck cannot be finalized.

Unblock actions:
1. Decide mandatory vs optional MCP segment.
2. If mandatory, perform venue-like auth rehearsal.

### B3. Legacy route coexistence increases accidental path risk

Impact:
- Inconsistent behavior in live browser tabs.

Unblock actions:
1. Route-lock presenter to /ui.
2. Remove bookmarks/links to legacy pages.
3. Optionally feature-flag or disable /analyze in demo profile.

## 4) Mitigation Tracker

Immediate mitigations that should be executed now:
1. Create clean demo branch and freeze scope.
2. Lock runtime environment and pass contract tests.
3. Rehearse scripted path: triage -> deep -> optional MCP.
4. Prepare fallback narratives and evidence artifacts.

## 5) Acceptance Criteria To Close This Risk Log

Close this document when all are true:
1. Primary demo narrative is chosen and documented.
2. /ui-only route policy is confirmed for stage demo.
3. Canonical test environment is defined and tests pass.
4. OAuth/MCP requirement decision is finalized with backup path.
5. Owner and deadline are assigned for each High/Critical risk.
