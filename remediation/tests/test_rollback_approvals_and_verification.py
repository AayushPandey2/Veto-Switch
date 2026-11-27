"""Tests for proposal hash binding, approvals, drift, receipts, readback, and verification."""

from __future__ import annotations

from datetime import timedelta

from agent_core.context import ProducerContext
from remediation.recovery import (
    ExecutorCapabilities,
    RollbackContext,
    reconcile_post_rollback_readback,
    revalidate_rollback_preconditions,
    validate_rollback_approval_binding,
    validate_rollback_receipt,
    verify_post_rollback,
)
from remediation.rollback import RollbackIntelligenceEngine
from remediation.rollback_demos import (
    _NOW,
    _REV,
    _base_deployment,
    _degraded_25pct_decision,
    _feature_state,
    _safe_checkpoint_5pct,
)
from shared.enums import (
    ActorType,
    ApprovalStatus,
    EvidenceProvenance,
    IncidentState,
    OperationOutcome,
    RollbackReasonCode,
    RollbackVerificationOutcome,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import ApprovalDecision, OperationReceipt, RollbackProposal, VerificationResult
from shared.serialization import sha256_text


def _sample_proposal() -> RollbackProposal:
    engine = RollbackIntelligenceEngine()
    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        current_observed_exposure=25,
        current_targeting_version="v2",
        current_observed_feature_state=_feature_state("search_v2", True),
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision=_REV,
        deployment_evidence=_base_deployment(),
        rollout_decision=dec25,
        triggering_telemetry=met25,
        current_legacy_feature_state=_feature_state("search_v1", False),
        executor_capabilities=ExecutorCapabilities(
            supports_boolean=True, supports_targeting=True, fallback_verified=True
        ),
        evaluation_timestamp=_NOW,
    )
    res = engine.analyze(ctx, history=[cp5])
    assert res.proposal is not None
    return res.proposal


def test_approval_binding_rejects_tampering_expiry_reuse_and_non_human() -> None:
    prop = _sample_proposal()
    human = ProducerContext(
        producer_id="op_alice", actor_type=ActorType.HUMAN_OPERATOR, authenticated=True
    )
    ai = ProducerContext(producer_id="ai", actor_type=ActorType.AI_AGENT, authenticated=True)
    appr = ApprovalDecision(
        approval_id="appr_rb_1",
        proposal_id=prop.proposal_id,
        proposal_hash=prop.proposal_hash or "",
        incident_id=prop.incident_id,
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_rb_1",
        decided_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(minutes=10),
        authorization_context_ref="auth_rb_1",
    )

    assert validate_rollback_approval_binding(
        proposal=prop, approval=appr, producer=human, reference_time=_NOW
    ).allowed
    assert not validate_rollback_approval_binding(
        proposal=prop, approval=appr, producer=ai, reference_time=_NOW
    ).allowed
    assert not validate_rollback_approval_binding(
        proposal=prop,
        approval=appr.model_copy(update={"proposal_hash": sha256_text("tampered")}),
        producer=human,
        reference_time=_NOW,
    ).allowed
    assert not validate_rollback_approval_binding(
        proposal=prop,
        approval=appr.model_copy(update={"expires_at": _NOW - timedelta(seconds=1)}),
        producer=human,
        reference_time=_NOW,
    ).allowed
    assert not validate_rollback_approval_binding(
        proposal=prop,
        approval=appr,
        producer=human,
        consumed_approval_ids={"appr_rb_1"},
        reference_time=_NOW,
    ).allowed


def test_state_drift_detection() -> None:
    prop = _sample_proposal()
    ok = revalidate_rollback_preconditions(
        proposal=prop,
        observed_feature_state=_feature_state("search_v2", True),
        observed_targeting_version="v2",
        observed_deployment_identity=_REV,
    )
    assert ok.allowed

    drift_ver = revalidate_rollback_preconditions(
        proposal=prop,
        observed_feature_state=_feature_state("search_v2", True),
        observed_targeting_version="v3",
    )
    assert not drift_ver.allowed
    assert drift_ver.reason_code == RollbackReasonCode.CURRENT_TARGETING_CONFLICT.value


def test_receipt_readback_and_verification_outcomes() -> None:
    prop = _sample_proposal()
    rcpt = OperationReceipt(
        operation_id="op_rb_1",
        incident_id=prop.incident_id,
        proposal_id=prop.proposal_id,
        approval_id="appr_rb_1",
        environment="demo-staging",
        target_feature="search_v2",
        requested_state=True,
        observed_state=True,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key="idem_rb_1",
        executed_at=_NOW,
        evidence_ids=["art_op"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )

    assert validate_rollback_receipt(
        proposal=prop, approval=None, receipt=rcpt, seen_operation_ids={"op_rb_1"}
    ).duplicate
    assert (
        validate_rollback_receipt(
            proposal=prop,
            approval=None,
            receipt=rcpt.model_copy(update={"outcome": OperationOutcome.TIMED_OUT}),
        ).status
        == "execution_outcome_unknown"
    )

    rb_bad = reconcile_post_rollback_readback(
        proposal=prop,
        management_readback=_feature_state("search_v2", True),
        application_observed_exposure=25,
        legacy_feature_state=_feature_state("search_v1", False),
    )
    assert not rb_bad.matched

    rb_ok = reconcile_post_rollback_readback(
        proposal=prop,
        management_readback=_feature_state("search_v2", True),
        application_observed_exposure=5,
        legacy_feature_state=_feature_state("search_v1", False),
    )
    sec_ok = VerificationResult(
        verification_id="ver_post",
        incident_id=prop.incident_id,
        test_id="test_post",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_post"],
        completed_at=_NOW,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    partial_ver = verify_post_rollback(
        proposal=prop,
        receipt=rcpt,
        readback=rb_ok,
        security_verification=sec_ok,
        expected_revision=_REV,
    )
    assert partial_ver.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFIED
    assert partial_ver.recommended_incident_state == IncidentState.ROLLOUT_PAUSED
    assert partial_ver.full_containment_restored is False
