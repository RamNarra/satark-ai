# SATARK Two-Phase Analysis Contract

Last updated: 2026-04-08

## Goals

- Keep first response fast and safe with triage-first behavior.
- Keep deep analysis explicit and replay-safe.
- Keep stream and REST payloads schema-compatible with version metadata.

## Versions

- contract_version: 2026-04-two-phase-v1
- analysis_stage_version: 1

## Endpoints

### 1) POST /api/analyze (Phase 1: triage)

Server normalizes incoming options to triage mode.

- deep_analysis: false
- fast_first: true
- generate_report: false
- trigger_mcp_actions: false

Accepted response example:

```json
{
  "run_id": "run_abc",
  "case_id": "case_123",
  "session_id": "sess_xyz",
  "status": "accepted",
  "contract_version": "2026-04-two-phase-v1",
  "analysis_stage_version": 1,
  "analysis_stage": "triage",
  "source_run_id": null,
  "eligible_for_deep": true,
  "deep_reason": "Phase-1 triage accepted. You can trigger deep analysis when needed.",
  "deep_reason_code": "TRIAGE_ACCEPTED_DEEP_AVAILABLE",
  "deep_analysis_url": "/api/analyze/deep",
  "stream_url": "/api/stream/run_abc",
  "result_url": "/api/result/run_abc"
}
```

### 2) POST /api/analyze/deep (Phase 2: deep)

Request body:

```json
{
  "source_run_id": "run_abc",
  "generate_report": true,
  "trigger_mcp_actions": false,
  "stream": true
}
```

Request headers:

- Idempotency-Key: client-generated stable key per source_run_id

Rules:

- source_run_id must exist.
- source_run_id must reference a triage run, not deep.
- source triage run must be eligible for deep analysis.
- if a matching deep run is already active (or same idempotency key replay), server returns the existing deep run acceptance payload.

Deep accepted response example:

```json
{
  "run_id": "run_deep_001",
  "case_id": "case_123",
  "session_id": "sess_xyz",
  "status": "accepted",
  "contract_version": "2026-04-two-phase-v1",
  "analysis_stage_version": 1,
  "analysis_stage": "deep",
  "source_run_id": "run_abc",
  "eligible_for_deep": false,
  "deep_reason": "Deep analysis accepted for this case.",
  "deep_reason_code": "DEEP_ACCEPTED",
  "stream_url": "/api/stream/run_deep_001",
  "result_url": "/api/result/run_deep_001",
  "idempotent_replay": false
}
```

Replay response example:

```json
{
  "run_id": "run_deep_001",
  "analysis_stage": "deep",
  "source_run_id": "run_abc",
  "idempotent_replay": true
}
```

## Result Polling: GET /api/result/{run_id}

Pending/running response includes stage-safe metadata:

```json
{
  "run_id": "run_abc",
  "case_id": "case_123",
  "status": "running",
  "contract_version": "2026-04-two-phase-v1",
  "analysis_stage_version": 1,
  "analysis_stage": "triage",
  "source_run_id": null,
  "eligible_for_deep": true,
  "deep_reason": "Phase-1 triage is in progress. Deep analysis can be requested after triage acceptance.",
  "deep_reason_code": "TRIAGE_IN_PROGRESS",
  "message": "Run still in progress"
}
```

Completed response includes:

- analysis_stage
- source_run_id
- eligible_for_deep
- deep_reason
- deep_reason_code
- deep_analysis_endpoint when eligible

## SSE Events

All events include:

- run_id
- timestamp
- contract_version
- analysis_stage_version
- analysis_stage when available
- source_run_id when available

Important event names:

- run.accepted
- run.started
- run.classified
- triage.completed
- deep.completed
- run.completed
- run.failed

## Client Behavior Guidance

- Keep triage and deep messages in one case thread keyed by case_id.
- Branch UI logic by deep_reason_code instead of parsing deep_reason text.
- Treat idempotent_replay=true as resume/rejoin of existing deep run, not a new conversation branch.
