# Killswitch X — Event Catalog

`shared/enums.py::EventType` preserves all 23 Prompt 01 event names and adds granular Prompt 02 lifecycle events. Every event is classified by `agent_core/events.py::classify_event()` into `DOMAIN_EVENT`, `COMMAND`, `EXTERNAL_NOTIFICATION`, `INTERNAL_DECISION`, or `REJECTED_DIAGNOSTIC`.

## 1. Event Taxonomy & Effects

| Event Type | Producer(s) | Classification | Primary State Effect | Idempotency & Failure Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `finding_received` | `security_scanner`, `security_verifier`, `system` | `DOMAIN_EVENT` | Initializes `RECEIVED` (seq 1) | Unique `event_id`; rejects live fixture findings |
| `verification_requested` / `validation_requested` | `deterministic_engine`, `human_operator`, `system` | `COMMAND` | `RECEIVED`/`UNVERIFIED` → `VALIDATION_REQUESTED` | Emits non-privileged verification request |
| `reproduction_confirmed` / `vulnerability_reproduced` | `security_verifier` | `EXTERNAL_NOTIFICATION` | `VALIDATION_REQUESTED` → `REPRODUCED` | Requires `evidence_existence`, `evidence_provenance`, matching env/rev |
| `reproduction_not_confirmed`, `verification_inconclusive`, `verification_failed`, `verification_timeout` | `security_verifier` | `EXTERNAL_NOTIFICATION` | `VALIDATION_REQUESTED` → `UNVERIFIED` | Preserves suspected finding; routes safely |
| `investigation_completed` | `deterministic_engine`, `ai_agent` | `DOMAIN_EVENT` | Non-transition (sets `investigation_id`) | Validated against finding & incident IDs |
| `mapping_matched` / `flag_mapped` | `deterministic_engine`, `ai_agent`, `human_operator` | `DOMAIN_EVENT` | `REPRODUCED`/`UNMAPPED` → `FLAG_MAPPED` | Requires declared registry flag & `manual_review_required=False` |
| `mapping_unmapped`, `mapping_ambiguous`, `mapping_failed` | `deterministic_engine`, `ai_agent` | `DOMAIN_EVENT` | `REPRODUCED` → `UNMAPPED` | Halts automated progression; requests review |
| `containment_proposed` | `deterministic_engine`, `ai_agent`, `human_operator` | `INTERNAL_DECISION` | `FLAG_MAPPED`/recovery → `CONTAINMENT_PROPOSED` | Requires valid `proposal_hash`, `approval_required=True`, registry check |
| `approval_requested` | `deterministic_engine` | `COMMAND` | `CONTAINMENT_PROPOSED` → `AWAITING_APPROVAL` | Halts workflow until human decision |
| `approval_granted` | `human_operator` | `EXTERNAL_NOTIFICATION` | `AWAITING_APPROVAL` → `APPLYING` | Requires 8-part approval, freshness, and drift checks; emits `DownstreamRequest` with stable `idempotency_key` |
| `approval_rejected`, `approval_expired`, `containment_proposal_invalidated` | `human_operator`, `system` | `EXTERNAL_NOTIFICATION` | `AWAITING_APPROVAL` → `REJECTED` | Supersedes proposal; emits 0 execution requests |
| `flag_update_success` / `flag_change_executed` | `platform_executor` | `EXTERNAL_NOTIFICATION` | `APPLYING`/`CHANGE_FAILED` → `CONTAINMENT_TEST_PENDING` | Requires trusted `OperationReceipt` (`provenance != llm_interpretation`) |
| `flag_update_failed` / `flag_change_failed`, `flag_update_outcome_unknown` | `platform_executor`, `system` | `EXTERNAL_NOTIFICATION` | `APPLYING` → `CHANGE_FAILED` | Unknown outcome emits reconciliation request; never blind-retries |
| `flag_state_observed` | `platform_executor`, `security_verifier` | `EXTERNAL_NOTIFICATION` | Non-transition (updates `observed_feature_state`) | Rejects `UNKNOWN` / `UNAVAILABLE` as disabled |
| `functional_smoke_test_passed` / `failed` | `security_verifier`, `platform_executor` | `EXTERNAL_NOTIFICATION` | Non-transition (sets `functional_smoke_test_passed`) | Required for `CONTAINED` |
| `containment_confirmed` / `containment_verified` | `security_verifier`, `deterministic_engine` | `DOMAIN_EVENT` | `CONTAINMENT_TEST_PENDING` → `CONTAINED` | Requires readback, security regression pass, smoke pass, post-op timestamps |
| `containment_verification_failed` / `containment_failed` | `security_verifier` | `EXTERNAL_NOTIFICATION` | `CONTAINMENT_TEST_PENDING` → `CONTAINMENT_FAILED` | Requires stronger containment proposal |
| `patch_requested` | `deterministic_engine` | `COMMAND` | `CONTAINED`/`PATCH_FAILED` → `PATCH_PENDING` | Initiates patch workflow |
| `patch_proposed` | `deterministic_engine`, `ai_agent` | `INTERNAL_DECISION` | Non-transition (records `active_patch_id`/`hash`) | Does NOT imply tested or deployed |
| `patch_test_passed` | `security_verifier` | `EXTERNAL_NOTIFICATION` | `PATCH_PENDING` → `PATCH_TESTED` | Requires matching revision, hash, and all security + functional tests passing |
| `patch_test_failed`, `patch_validation_failed`, `patch_test_infrastructure_error` | `security_verifier` | `EXTERNAL_NOTIFICATION` | `PATCH_PENDING` → `PATCH_FAILED` | Blocks rollout planning |
| `deployment_observed` / `patch_deployment_observed` | `platform_executor`, `system` | `EXTERNAL_NOTIFICATION` | Non-transition (records `verified_deployment_revision`) | Requires `deployment_status="observed"` and `addressable=True` |
| `rollout_plan_created` | `deterministic_engine` | `INTERNAL_DECISION` | `PATCH_TESTED`/`ROLLOUT_PAUSED` → `ROLLOUT_PENDING` | Requires tested patch + observed deployment + valid `RolloutPlan` |
| `rollout_stage_approved` | `human_operator` | `EXTERNAL_NOTIFICATION` | Non-transition in `ROLLOUT_PENDING` (or resumes `ROLLOUT_PAUSED`) | Single-use stage-specific approval; emits stage request |
| `rollout_stage_applied`, `rollout_stage_observed`, `rollout_metrics_received`, `rollout_advance_proposed` | `platform_executor`, `system`, `deterministic_engine` | Mixed | Non-transition (updates `RolloutStageRecord`) | Preserves synthetic telemetry provenance |
| `rollout_hold`, `rollout_failed` | `deterministic_engine`, `platform_executor` | `INTERNAL_DECISION` | `ROLLOUT_PENDING` → `ROLLOUT_PAUSED` | Fail-closed pause on missing telemetry |
| `rollback_proposed` | `deterministic_engine` | `INTERNAL_DECISION` | `ROLLOUT_PENDING`/`ROLLOUT_PAUSED` → `ROLLBACK_PROPOSED` | Requires `approval_required=True` and `rollback_safety` |
| `rollback_approved`, `rollback_applied`, `rollback_verification_failed` | `human_operator`, `platform_executor`, `security_verifier` | `EXTERNAL_NOTIFICATION` | Non-transition inside `ROLLBACK_PROPOSED` | Never assumes legacy target is safe without verification |
| `rollback_verification_passed` | `security_verifier` | `EXTERNAL_NOTIFICATION` | `ROLLBACK_PROPOSED` → `CONTAINED` | Returns to `CONTAINED`, never `RECOVERED` |
| `rollout_completed` | `deterministic_engine` | `DOMAIN_EVENT` | `ROLLOUT_PENDING` → `RECOVERED` | Requires 100% stage observed/completed + final verification pass |
| `incident_reopened` | `human_operator`, `security_verifier` | `DOMAIN_EVENT` | `RECOVERED` → `VALIDATION_REQUESTED` | Requires newly verified evidence |
