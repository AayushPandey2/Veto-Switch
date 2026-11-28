# Killswitch X — Incident State Machine

The authoritative transition table and non-transition event rules live in [`agent_core/transitions.py`](../agent_core/transitions.py) and are evaluated by [`agent_core/state_machine.py`](../agent_core/state_machine.py).

## 1. Status Separation

Killswitch X strictly separates eight distinct status concepts rather than collapsing them into one field:
1. **Incident Lifecycle State (`IncidentState`):** Top-level orchestration state (`RECEIVED` .. `RECOVERED` / failure states).
2. **Vulnerability Finding Status (`FindingStatus`):** `suspected` vs. `reproduced`.
3. **Approval Status (`ApprovalStatus`):** `pending`, `approved`, `rejected`, `expired`, `invalidated`.
4. **External Operation Outcome (`OperationOutcome`):** `succeeded`, `failed`, `rejected`, `timed_out`, `unknown`.
5. **Patch Lifecycle Status (`PatchStatus`):** `patch_proposed`, `patch_tested`, `patch_failed`, `patch_deployed`.
6. **Deployment Status (`DeploymentStatus`):** `observed`, `pending`, `failed`, `missing`, `unknown`.
7. **Rollout Stage (`RolloutStageRecord.status`):** Subordinate per-percentage tracking (`5%`, `25%`, `50%`, `100%`) inside `ROLLOUT_PENDING`.
8. **Evidence Completeness (`EvidenceCompleteness`):** `complete`, `partial`, `incomplete`.

## 2. State Diagram (Generated from `TRANSITION_RULES`)

```mermaid
stateDiagram-v2
    [*] --> RECEIVED : finding_received
    RECEIVED --> VALIDATION_REQUESTED : verification_requested
    RECEIVED --> VALIDATION_REQUESTED : validation_requested
    VALIDATION_REQUESTED --> REPRODUCED : reproduction_confirmed
    VALIDATION_REQUESTED --> REPRODUCED : vulnerability_reproduced
    VALIDATION_REQUESTED --> UNVERIFIED : reproduction_not_confirmed
    VALIDATION_REQUESTED --> UNVERIFIED : verification_inconclusive
    VALIDATION_REQUESTED --> UNVERIFIED : verification_failed
    VALIDATION_REQUESTED --> UNVERIFIED : verification_timeout
    VALIDATION_REQUESTED --> UNVERIFIED : vulnerability_unverified
    REPRODUCED --> FLAG_MAPPED : mapping_matched
    REPRODUCED --> FLAG_MAPPED : flag_mapped
    REPRODUCED --> UNMAPPED : mapping_unmapped
    REPRODUCED --> UNMAPPED : mapping_ambiguous
    REPRODUCED --> UNMAPPED : mapping_failed
    REPRODUCED --> UNMAPPED : flag_mapping_failed
    FLAG_MAPPED --> CONTAINMENT_PROPOSED : containment_proposed
    CONTAINMENT_PROPOSED --> AWAITING_APPROVAL : approval_requested
    AWAITING_APPROVAL --> APPLYING : approval_granted
    AWAITING_APPROVAL --> REJECTED : approval_rejected
    AWAITING_APPROVAL --> REJECTED : approval_expired
    AWAITING_APPROVAL --> REJECTED : containment_proposal_invalidated
    APPLYING --> CONTAINMENT_TEST_PENDING : flag_update_success
    APPLYING --> CONTAINMENT_TEST_PENDING : flag_change_executed
    APPLYING --> CHANGE_FAILED : flag_update_failed
    APPLYING --> CHANGE_FAILED : flag_change_failed
    APPLYING --> CHANGE_FAILED : flag_update_outcome_unknown
    CONTAINMENT_TEST_PENDING --> CONTAINED : containment_confirmed
    CONTAINMENT_TEST_PENDING --> CONTAINED : containment_verified
    CONTAINMENT_TEST_PENDING --> CONTAINMENT_FAILED : containment_verification_failed
    CONTAINMENT_TEST_PENDING --> CONTAINMENT_FAILED : containment_failed
    CONTAINED --> PATCH_PENDING : patch_requested
    PATCH_PENDING --> PATCH_TESTED : patch_test_passed
    PATCH_PENDING --> PATCH_FAILED : patch_test_failed
    PATCH_PENDING --> PATCH_FAILED : patch_validation_failed
    PATCH_PENDING --> PATCH_FAILED : patch_test_infrastructure_error
    PATCH_TESTED --> ROLLOUT_PENDING : rollout_plan_created
    ROLLOUT_PENDING --> ROLLOUT_PAUSED : rollout_hold
    ROLLOUT_PENDING --> ROLLOUT_PAUSED : rollout_failed
    ROLLOUT_PENDING --> ROLLBACK_PROPOSED : rollback_proposed
    ROLLOUT_PENDING --> RECOVERED : rollout_completed
    UNVERIFIED --> VALIDATION_REQUESTED : verification_requested
    UNMAPPED --> FLAG_MAPPED : mapping_matched
    REJECTED --> CONTAINMENT_PROPOSED : containment_proposed
    CHANGE_FAILED --> CONTAINMENT_PROPOSED : containment_proposed
    CHANGE_FAILED --> CONTAINMENT_TEST_PENDING : flag_update_success
    CONTAINMENT_FAILED --> CONTAINMENT_PROPOSED : containment_proposed
    PATCH_FAILED --> PATCH_PENDING : patch_requested
    ROLLOUT_PAUSED --> ROLLOUT_PENDING : rollout_plan_created
    ROLLOUT_PAUSED --> ROLLOUT_PENDING : rollout_stage_approved
    ROLLOUT_PAUSED --> ROLLBACK_PROPOSED : rollback_proposed
    ROLLBACK_PROPOSED --> CONTAINED : rollback_verification_passed
    RECOVERED --> VALIDATION_REQUESTED : incident_reopened
    RECOVERED --> [*]
```

## 3. Non-Transition Context Events

Events in `NON_TRANSITION_RULES` update `IncidentAggregate` metadata without changing `current_state`:
- `investigation_completed`, `investigation_requested`, `investigation_failed`, `mapping_requested`
- `execution_requested`, `execution_accepted`, `flag_state_observed`
- `containment_verification_requested`, `containment_verification_passed`, `functional_smoke_test_passed`, `functional_smoke_test_failed`
- `patch_proposed`, `patch_test_requested`, `patch_test_completed`, `deployment_observed`, `patch_deployment_observed`
- `rollout_stage_proposed`, `rollout_stage_approved`, `rollout_stage_applied`, `rollout_stage_observed`, `rollout_metrics_received`, `rollout_advance_proposed`, `rollout_decision_recorded`
- `rollback_approved`, `rollback_rejected`, `rollback_applied`, `rollback_verification_failed`
- `operation_retry_requested`, `operation_retry_exhausted`, `integration_unavailable`, `manual_review_requested`, `approval_invalidated`, `evidence_exported`

## 4. Terminal & Reopening Behavior

`RECOVERED` permits **only** non-transition diagnostic/export events (`evidence_exported`, `manual_review_requested`) and one explicit audited reopening transition (`incident_reopened` → `VALIDATION_REQUESTED`) guarded by `evidence_existence` when newly verified evidence invalidates recovery.
