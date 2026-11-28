"""Tests for VerifiedSafeState recording, immutable history store, and invalidation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from remediation.recovery import (
    RollbackContext,
    SafeStateCheckpointInput,
    SafeStateHistoryStore,
    record_verified_safe_state,
    resolve_last_verified_safe_state,
)
from remediation.rollback_demos import (
    _NOW,
    _REV,
    _base_deployment,
    _feature_state,
    _safe_checkpoint_5pct,
)
from shared.enums import (
    ApprovalStatus,
    EvidenceProvenance,
    OperationOutcome,
    RollbackReasonCode,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import (
    ApprovalDecision,
    LatencyStats,
    MetricSnapshot,
    OperationReceipt,
    RolloutDecision,
    VerificationResult,
)
from shared.serialization import sha256_text


def test_safe_state_history_store_is_immutable_and_ordered() -> None:
    store = SafeStateHistoryStore()
    cp1 = _safe_checkpoint_5pct()
    cp2 = cp1.model_copy(
        update={
            "safe_state_id": "safe_second",
            "configured_exposure_percentage": 25,
            "verified_at": cp1.verified_at + timedelta(minutes=5),
        }
    )
    store.record(cp2)
    store.record(cp1)
    ordered = store.list_for_incident("inc_demo_10")
    assert [c.safe_state_id for c in ordered] == [cp1.safe_state_id, "safe_second"]

    with pytest.raises(ValueError, match="immutable"):
        store.record(cp1.model_copy(update={"configured_exposure_percentage": 99}))


def test_record_verified_safe_state_rejects_uncontained_legacy() -> None:
    appr = ApprovalDecision(
        approval_id="appr_1",
        proposal_id="stage_5",
        proposal_hash=sha256_text("stage_5"),
        incident_id="inc_demo_10",
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_1",
        decided_at=_NOW - timedelta(minutes=10),
        expires_at=_NOW + timedelta(minutes=10),
        authorization_context_ref="auth_1",
    )
    rcpt = OperationReceipt(
        operation_id="op_1",
        incident_id="inc_demo_10",
        proposal_id="stage_5",
        approval_id="appr_1",
        environment="demo-staging",
        target_feature="search_v2",
        requested_state=True,
        observed_state=True,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key="idem_1",
        executed_at=_NOW - timedelta(minutes=9),
        evidence_ids=["art_1"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    met = MetricSnapshot(
        snapshot_id="met_1",
        incident_id="inc_demo_10",
        environment="demo-staging",
        feature_id="search_v2",
        observation_window_seconds=45,
        observed_at=_NOW - timedelta(minutes=5),
        request_count=200,
        failed_request_count=1,
        error_rate=0.005,
        latency_ms=LatencyStats(p50_ms=15.0, p95_ms=35.0, p99_ms=50.0),
        security_regression_passed=True,
        observed_rollout_stage_percentage=5,
        provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        evidence_ids=["art_met_1"],
    )
    ver = VerificationResult(
        verification_id="ver_1",
        incident_id="inc_demo_10",
        test_id="test_1",
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_ver_1"],
        completed_at=_NOW - timedelta(minutes=6),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    dec = RolloutDecision(
        decision_id="rdec_1",
        plan_id="rplan_1",
        incident_id="inc_demo_10",
        current_stage_id="stage_5",
        proposed_next_stage_id="stage_25",
        decision_type=RolloutDecisionType.ADVANCE,
        evaluated_guardrails=["max_error_rate"],
        passed_guardrails=["max_error_rate"],
        explanation="Healthy.",
        evidence_ids=["art_met_1"],
    )
    with pytest.raises(ValueError, match="vulnerable legacy"):
        record_verified_safe_state(
            SafeStateCheckpointInput(
                incident_id="inc_demo_10",
                plan_id="rplan_1",
                stage_id="stage_5",
                environment="demo-staging",
                feature_name="search_v2",
                implementation_id="search_service_v2",
                configured_exposure_percentage=5,
                global_feature_state=True,
                approval=appr,
                receipt=rcpt,
                readback_state=_feature_state("search_v2", True),
                application_observed_exposure=5,
                deployment_evidence=_base_deployment(),
                security_verification=ver,
                functional_verification=ver,
                telemetry_snapshot=met,
                rollout_decision=dec,
                legacy_feature_states={"search_v1": _feature_state("search_v1", True)},
            )
        )


def test_resolve_invalidates_revision_stale_and_routing_conflicts() -> None:
    cp = _safe_checkpoint_5pct()
    ctx_rev = RollbackContext(
        incident_id="inc_demo_10",
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision="rev_different",
        evaluation_timestamp=_NOW,
    )
    res_rev = resolve_last_verified_safe_state([cp], ctx_rev)
    assert res_rev.known is False
    assert RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH in res_rev.reason_codes

    ctx_stale = RollbackContext(
        incident_id="inc_demo_10",
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision=_REV,
        evaluation_timestamp=_NOW + timedelta(days=3),
    )
    res_stale = resolve_last_verified_safe_state([cp], ctx_stale)
    assert res_stale.known is False
    assert RollbackReasonCode.SAFE_STATE_STALE in res_stale.reason_codes

    ctx_route = RollbackContext(
        incident_id="inc_demo_10",
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision=_REV,
        routing_changed=True,
        evaluation_timestamp=_NOW,
    )
    res_route = resolve_last_verified_safe_state([cp], ctx_route)
    assert res_route.known is False
    assert RollbackReasonCode.CURRENT_TARGETING_CONFLICT in res_route.reason_codes
