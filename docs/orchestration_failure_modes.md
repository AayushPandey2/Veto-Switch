# Killswitch X — Orchestration Failure Modes & Retry Classification

## 1. Explicit Failure States & Reason Codes

| Failure Condition | Routed State | Recovery Path |
| :--- | :--- | :--- |
| Reproduction failed, inconclusive, or timed out | `UNVERIFIED` | `verification_requested` → `VALIDATION_REQUESTED` |
| No flag or ambiguous candidate flags | `UNMAPPED` | `mapping_matched` (after registry update/review) → `FLAG_MAPPED` |
| Human rejected or approval expired/invalidated | `REJECTED` | `containment_proposed` (new proposal) → `CONTAINMENT_PROPOSED` |
| External Flagsmith write failed or outcome unknown | `CHANGE_FAILED` | `flag_update_success` (reconciled) → `CONTAINMENT_TEST_PENDING`, or `containment_proposed` → `CONTAINMENT_PROPOSED` |
| Post-change security regression or smoke test failed | `CONTAINMENT_FAILED` | `containment_proposed` (stronger mitigation) → `CONTAINMENT_PROPOSED` |
| Candidate patch validation, test, or runner error | `PATCH_FAILED` | `patch_requested` (new candidate) → `PATCH_PENDING` |
| Rollout telemetry missing or non-rollback hold | `ROLLOUT_PAUSED` | `rollout_plan_created` / `rollout_stage_approved` → `ROLLOUT_PENDING`, or `rollback_proposed` → `ROLLBACK_PROPOSED` |
| Rollout health guardrail breached | `ROLLBACK_PROPOSED` | `rollback_verification_passed` (after human rollback approval) → `CONTAINED` |

## 2. Bounded Retry & Reconciliation (`agent_core/retry_policy.py`)

`classify_error(exc, is_privileged_write=...)` separates errors into three classes:
- **`RETRYABLE`:** Read-only `IntegrationUnavailableError`, `TelemetryUnavailableError`, `TestRunnerError`, `LLMProviderError`, `LLMTimeoutError`, `ConcurrencyConflictError`. Retried under bounded `max_attempts`, exponential backoff (`max_backoff_seconds`), and `overall_deadline_seconds`.
- **`NON_RETRYABLE`:** Validation, approval, unknown feature, ambiguous mapping, idempotency conflict, and invalid transition errors. Fails immediately.
- **`RECONCILIATION_REQUIRED`:** Timeouts or `IntegrationUnavailableError` when `is_privileged_write=True`. Never blindly retried; routes to `CHANGE_FAILED` and emits a read-only reconciliation request (`reconcile_operation_and_feature_state`).
