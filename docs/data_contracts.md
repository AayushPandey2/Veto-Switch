# Killswitch X — Shared Data Contracts

All shared models live in [`shared/schemas.py`](../shared/schemas.py), backed by [`shared/enums.py`](../shared/enums.py) and [`shared/validation.py`](../shared/validation.py).

## 1. Model Inventory

| Model | Purpose | Primary Producer | Primary Consumers |
| :--- | :--- | :--- | :--- |
| `Finding` | Normalized security vulnerability report (`suspected` / `reproduced`) | `security` | `agent_core`, `remediation`, `platform` |
| `InvestigationSummary` | Structured AI/deterministic analysis separating facts from assumptions | `agent_core` | `platform`, `remediation` |
| `MappingResult` | Route/component-to-flag mapping (`matched` / `ambiguous` / `unmapped`) | `agent_core` | `platform` |
| `GraphNode`, `GraphEdge`, `DependencyGraph` | Illustrative application dependency graph | `config` / `agent_core` | `agent_core`, `platform` |
| `ContainmentOption` | Scored containment strategy candidate (policy estimates only) | `agent_core` | `agent_core`, `platform` |
| `ContainmentProposal` | Hash-bound operational flag change proposal (`approval_required=True`) | `agent_core` | `platform` |
| `ApprovalDecision` | Authenticated human approval bound to `proposal_id` & `proposal_hash` | `platform` | `platform`, `agent_core` |
| `FeatureState` | Read-only flag observation (`observed` vs `unavailable`/`unknown`) | `platform` | `agent_core`, `remediation` |
| `OperationReceipt` | Privileged Flagsmith execution receipt + readback state | `platform` | `agent_core`, `remediation` |
| `VerificationResult` | Pre/post-containment & post-patch security check outcome | `security` | `agent_core`, `remediation`, `platform` |
| `PatchProposal` | Allowlist-bounded candidate code patch (`review_required=True`) | `remediation` | `security`, `platform` |
| `IndividualTestOutcome`, `PatchTestResult` | Isolated patch test run results with revision & hash checks | `security` | `remediation`, `platform` |
| `DeploymentEvidence` | Observed deployment revision & flag addressability record | `platform` | `remediation` |
| `RolloutGuardrailConfig`, `RolloutStage`, `RolloutPlan` | Progressive exposure plan (default 5/25/50/100%) | `remediation` | `platform` |
| `LatencyStats`, `MetricSnapshot` | Telemetry snapshot (`None` = unknown; explicit provenance) | `platform` | `remediation` |
| `RolloutDecision` | Fail-closed stage evaluation (`advance` / `hold` / `rollback_proposed`) | `remediation` | `platform` |
| `RollbackProposal` | Human-reviewed rollback recommendation (never assumes legacy is safe) | `remediation` | `platform` |
| `CoverageFinding` | Route feature-flag coverage audit finding | `agent_core` | `platform`, `remediation` |
| `ArtifactReference` | SHA-256 content-hashed artifact metadata pointer | `security` / `platform` | All subsystems |
| `IncidentEvent` (+ 7 typed payloads) | Versioned immutable timeline event for deterministic replay | All via `platform` | `platform`, `remediation` |
| `EvidenceReport` | Complete exportable audit bundle with completeness status | `remediation` | `platform` |
| `IncidentRecord` | Persisted top-level incident state + concurrency version | `platform` | `agent_core` |

## 2. Numeric Units

| Field(s) | Unit | Valid Range | Unknown Representation |
| :--- | :--- | :--- | :--- |
| `error_rate`, `baseline_error_rate`, `max_error_rate` | Ratio | `[0.0, 1.0]` (`0.02` = 2%) | `None` |
| `max_error_rate_increase_pp` | Percentage points | `[0.0, 100.0]` | N/A (policy config) |
| `max_p95_latency_increase_percent` | Percent increase | `>= 0.0` | N/A (policy config) |
| `exposure_percentage`, `observed_rollout_stage_percentage` | Integer percent | `[0, 100]` | `None` |
| `p50_ms`, `p95_ms`, `p99_ms`, `baseline_p95_latency_ms` | Milliseconds | `>= 0.0` | `None` |
| `request_count`, `failed_request_count`, `minimum_request_count` | Request count | `>= 0` | `None` |
| `observation_window_seconds`, `minimum_observation_window_seconds` | Seconds | `>= 1` | N/A |
| `estimated_disruption`, `estimated_residual_risk`, `uncertainty`, `relative_policy_score` | Policy score | `[0.0, 1.0]` | N/A |
| `size_bytes` | Bytes | `>= 0` | `None` |

## 3. Local Model Validation vs. Cross-Service Evidence Verification

- **Local Pydantic validation** (`shared/schemas.py`, `shared/validation.py`) checks structural format, UTC timezone awareness, strict boolean/int types, path safety, SHA-256 hex format, and intra-model invariants (e.g., `reproduced` requires non-empty `evidence_ids`; `failed_request_count <= request_count`).
- **Cross-service verification** (future `platform` & `security` implementations) MUST confirm:
  1. Referenced `evidence_ids` actually exist in `EvidenceRepository` and belong to the target `incident_id`.
  2. `ApprovalDecision.authorization_context_ref` corresponds to a valid authenticated session in `ApprovalReader`.
  3. `OperationReceipt` originates from the trusted platform executor, never from an LLM output.

## 4. Phase 02 Persistence, Idempotency & Replay Extensions

Phase 02 implemented the in-memory reference orchestration engine (`agent_core/repositories/memory.py`, `agent_core/replay.py`, `agent_core/incident.py`) and added the following backwards-compatible extensions to `shared/`:
- **`shared/enums.py::EventType`:** Preserves all 23 Prompt 01 event names while adding granular intake, investigation, mapping, approval, execution, verification, patching, rollout, rollback, and operational events.
- **`shared/schemas.py::FindingReceivedPayload`:** Added optional default-safe fields (`environment`, `source_revision`, `is_synthetic_fixture`, `provenance`) for deterministic incident replay.
- **`shared/exceptions.py`:** Added `ConcurrencyConflictError`, `IdempotencyConflictError`, and `ReplayIntegrityError`.
- **`agent_core/incident.py::IncidentAggregate`:** Frozen aggregate enforcing versioned updates via `with_transition()`.

For future durable platform implementations (`platform/`) of `IncidentRepository` and `EventRepository`:
- **Transactional persistence:** Incident state updates, `IncidentEvent` appends, approval consumption, and operation reservation must commit in one atomic transaction.
- **Idempotency enforcement:** Unique constraints on `event_id`, `(incident_id, sequence_number)`, `idempotency_token`, and `operation_idempotency_key`.
- **Optimistic concurrency:** `commit_transition(..., expected_version=...)` rejects stale writers with `ConcurrencyConflictError`.
- **Approval invalidation:** Any proposal expiration or incident context shift invalidates pending approvals.
- **Deterministic replay:** Ascending per-incident `sequence_number` supports deterministic timeline reconstruction.
