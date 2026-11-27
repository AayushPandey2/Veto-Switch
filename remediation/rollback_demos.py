"""Offline reproducible demonstrations for Phase 10 Rollback Intelligence.

All scenarios use explicitly labeled synthetic/reference fixtures and never
claim live Flagsmith execution or live post-rollback verification.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_core.context import ProducerContext
from shared.enums import (
    ActorType,
    ApprovalStatus,
    DeploymentStatus,
    EvidenceProvenance,
    FeatureObservationStatus,
    IncidentState,
    OperationOutcome,
    RollbackStrategyType,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import (
    ApprovalDecision,
    DeploymentEvidence,
    FeatureState,
    LatencyStats,
    MetricSnapshot,
    OperationReceipt,
    RolloutDecision,
    VerificationResult,
    VerifiedSafeState,
)
from shared.serialization import sha256_text

from remediation.recovery import (
    ExecutorCapabilities,
    RollbackContext,
    SafeStateCheckpointInput,
    build_phase11_rollback_handoff,
    reconcile_post_rollback_readback,
    record_verified_safe_state,
    revalidate_rollback_preconditions,
    serialize_rollback_dashboard,
    validate_rollback_approval_binding,
    validate_rollback_receipt,
    verify_post_rollback,
)
from remediation.rollback import RollbackIntelligenceEngine

_NOW = datetime(2026, 11, 28, 2, 0, 0, tzinfo=UTC)
_REV = "rev_patched_789012"
_HASH = sha256_text("search_v2_patched")


def _base_deployment(revision: str = _REV) -> DeploymentEvidence:
    return DeploymentEvidence(
        deployment_id="dep_demo_001",
        environment="demo-staging",
        implementation_id="search_service_v2",
        feature_name="search_v2",
        source_revision=revision,
        implementation_hash=_HASH,
        deployed_at=_NOW - timedelta(minutes=30),
        deployment_status=DeploymentStatus.OBSERVED,
        addressable=True,
        evidence_ids=["art_dep_001"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )


def _feature_state(
    feature_name: str,
    enabled: bool,
    status: FeatureObservationStatus = FeatureObservationStatus.OBSERVED,
) -> FeatureState:
    return FeatureState(
        feature_id=f"feat_{feature_name}",
        environment="demo-staging",
        feature_name=feature_name,
        enabled=enabled,
        observation_status=status,
        observed_at=_NOW,
        evidence_ids=[f"art_fs_{feature_name}"],
    )


def _safe_checkpoint_5pct() -> VerifiedSafeState:
    appr = ApprovalDecision(
        approval_id="appr_stage_5pct",
        proposal_id="stage_5pct",
        proposal_hash=sha256_text("stage_5pct"),
        incident_id="inc_demo_10",
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_stage_5pct_001",
        decided_at=_NOW - timedelta(minutes=25),
        expires_at=_NOW + timedelta(minutes=30),
        authorization_context_ref="auth_ctx_demo",
    )
    receipt = OperationReceipt(
        operation_id="op_stage_5pct",
        incident_id="inc_demo_10",
        proposal_id="stage_5pct",
        approval_id="appr_stage_5pct",
        environment="demo-staging",
        target_feature="search_v2",
        requested_state=True,
        observed_state=True,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key="idem_stage_5pct",
        executed_at=_NOW - timedelta(minutes=24),
        evidence_ids=["art_op_5pct"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    healthy_metrics = MetricSnapshot(
        snapshot_id="met_5pct",
        incident_id="inc_demo_10",
        environment="demo-staging",
        feature_id="search_v2",
        observation_window_seconds=45,
        observed_at=_NOW - timedelta(minutes=20),
        request_count=250,
        failed_request_count=2,
        error_rate=0.008,
        latency_ms=LatencyStats(p50_ms=18.0, p95_ms=42.0, p99_ms=68.0),
        baseline_error_rate=0.005,
        baseline_p95_latency_ms=40.0,
        security_regression_passed=True,
        observed_rollout_stage_percentage=5,
        provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        evidence_ids=["art_met_5pct"],
    )
    sec_ver = VerificationResult(
        verification_id="ver_sec_5pct",
        incident_id="inc_demo_10",
        test_id="test_demo_10",
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_sec_5pct"],
        completed_at=_NOW - timedelta(minutes=21),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    func_ver = VerificationResult(
        verification_id="ver_func_5pct",
        incident_id="inc_demo_10",
        test_id="test_demo_10",
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_func_5pct"],
        completed_at=_NOW - timedelta(minutes=21),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    dec = RolloutDecision(
        decision_id="rdec_5pct",
        plan_id="rplan_demo_10",
        incident_id="inc_demo_10",
        current_stage_id="stage_5pct",
        proposed_next_stage_id="stage_25pct",
        decision_type=RolloutDecisionType.ADVANCE,
        evaluated_guardrails=["max_error_rate", "p95_latency", "security_regression"],
        passed_guardrails=["max_error_rate", "p95_latency", "security_regression"],
        explanation="5% stage healthy.",
        evidence_ids=["art_met_5pct"],
    )
    return record_verified_safe_state(
        SafeStateCheckpointInput(
            incident_id="inc_demo_10",
            plan_id="rplan_demo_10",
            stage_id="stage_5pct",
            environment="demo-staging",
            feature_name="search_v2",
            implementation_id="search_service_v2",
            configured_exposure_percentage=5,
            targeting_configuration={"exposure_percentage": 5},
            global_feature_state=True,
            approval=appr,
            receipt=receipt,
            readback_state=_feature_state("search_v2", True),
            application_observed_exposure=5,
            deployment_evidence=_base_deployment(),
            security_verification=sec_ver,
            functional_verification=func_ver,
            telemetry_snapshot=healthy_metrics,
            rollout_decision=dec,
            legacy_feature_states={"search_v1": _feature_state("search_v1", False)},
            verified_at=_NOW - timedelta(minutes=20),
        )
    )


def _degraded_25pct_decision() -> tuple[RolloutDecision, MetricSnapshot]:
    metrics = MetricSnapshot(
        snapshot_id="met_25pct",
        incident_id="inc_demo_10",
        environment="demo-staging",
        feature_id="search_v2",
        observation_window_seconds=45,
        observed_at=_NOW - timedelta(minutes=5),
        request_count=200,
        failed_request_count=14,
        error_rate=0.07,
        latency_ms=LatencyStats(p50_ms=30.0, p95_ms=95.0, p99_ms=150.0),
        baseline_error_rate=0.005,
        baseline_p95_latency_ms=40.0,
        security_regression_passed=True,
        observed_rollout_stage_percentage=25,
        provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        evidence_ids=["art_met_25pct"],
    )
    dec = RolloutDecision(
        decision_id="rdec_25pct",
        plan_id="rplan_demo_10",
        incident_id="inc_demo_10",
        current_stage_id="stage_25pct",
        decision_type=RolloutDecisionType.ROLLBACK_PROPOSED,
        evaluated_guardrails=["max_error_rate", "p95_latency", "security_regression"],
        passed_guardrails=["security_regression"],
        failed_guardrails=["max_error_rate", "p95_latency"],
        explanation="Error rate 7.0% exceeded 2.0% threshold at 25% stage.",
        evidence_ids=["art_met_25pct"],
    )
    return dec, metrics


def run_all_rollback_demos() -> dict[str, Any]:
    """Run primary synthetic error-spike scenario and Demos A-J offline."""
    engine = RollbackIntelligenceEngine()
    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    human = ProducerContext(
        producer_id="op_alice",
        actor_type=ActorType.HUMAN_OPERATOR,
        authenticated=True,
        provenance_mode="fixture",
    )

    outputs: dict[str, Any] = {}

    # 1. Primary Synthetic Error-Spike Rollback (25% -> 5% verified safe)
    ctx_spike = RollbackContext(
        incident_id="inc_demo_10",
        plan_id="rplan_demo_10",
        current_stage_id="stage_25pct",
        current_observed_exposure=25,
        current_targeting_configuration={"exposure_percentage": 25},
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
            supports_boolean=True,
            supports_targeting=True,
            declared_fallback_behavior="disabled_search_response",
            fallback_verified=True,
            fallback_verification_id="art_fb_001",
        ),
        evaluation_timestamp=_NOW,
        fixture_mode=True,
    )
    res_spike = engine.analyze(ctx_spike, history=[cp5])
    if res_spike.proposal is None:
        raise RuntimeError("Missing proposal in primary synthetic error spike demo.")
    appr_spike = ApprovalDecision(
        approval_id="appr_rb_spike",
        proposal_id=res_spike.proposal.proposal_id,
        proposal_hash=res_spike.proposal.proposal_hash or "",
        incident_id="inc_demo_10",
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_rb_spike_001",
        decided_at=_NOW,
        expires_at=_NOW + timedelta(minutes=15),
        authorization_context_ref="auth_ctx_demo",
    )
    rcpt_spike = OperationReceipt(
        operation_id="op_rb_spike",
        incident_id="inc_demo_10",
        proposal_id=res_spike.proposal.proposal_id,
        approval_id=appr_spike.approval_id,
        environment="demo-staging",
        target_feature="search_v2",
        requested_state=True,
        observed_state=True,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key="idem_rb_spike",
        executed_at=_NOW,
        evidence_ids=["art_op_rb_spike"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    rb_check = reconcile_post_rollback_readback(
        proposal=res_spike.proposal,
        management_readback=_feature_state("search_v2", True),
        application_observed_exposure=5,
        legacy_feature_state=_feature_state("search_v1", False),
        observed_targeting_configuration={"exposure_percentage": 5},
    )
    sec_post = VerificationResult(
        verification_id="ver_post_spike",
        incident_id="inc_demo_10",
        test_id="test_demo_10",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_post_spike"],
        completed_at=_NOW,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    ver_spike = verify_post_rollback(
        proposal=res_spike.proposal,
        receipt=rcpt_spike,
        readback=rb_check,
        security_verification=sec_post,
        expected_revision=_REV,
    )
    outputs["primary_synthetic_error_spike"] = serialize_rollback_dashboard(
        ctx=ctx_spike,
        analysis=res_spike,
        approval=appr_spike,
        receipt_result=validate_rollback_receipt(
            proposal=res_spike.proposal,
            approval=appr_spike,
            receipt=rcpt_spike,
            readback_completed=True,
        ),
        readback_result=rb_check,
        verification_result=ver_spike,
        final_incident_state=ver_spike.recommended_incident_state,
    )

    # Demo A — Confirmed security regression (must not keep 5% exposed)
    ctx_a = ctx_spike.model_copy(
        update={
            "security_regression_result": VerificationResult(
                verification_id="ver_sec_fail",
                incident_id="inc_demo_10",
                test_id="test_demo_10",
                phase=VerificationPhase.AFTER_PATCH,
                execution_status=TestExecutionStatus.TEST_FAILED,
                passed=False,
                vulnerability_reproduced=True,
                tested_revision=_REV,
                artifact_ids=["art_sec_fail"],
                completed_at=_NOW,
                provenance=EvidenceProvenance.REFERENCE_FIXTURE,
            )
        }
    )
    res_a = engine.analyze(ctx_a, history=[cp5])
    outputs["demo_a_confirmed_security_regression"] = {
        "selected_strategy": (
            res_a.selected_strategy.strategy_type.value if res_a.selected_strategy else None
        ),
        "proposed_state": res_a.proposal.proposed_state if res_a.proposal else None,
        "reason_codes": [r.value for r in res_a.reason_codes],
    }

    # Demo B — Unknown last verified-safe state
    res_b = engine.analyze(ctx_spike, history=[])
    outputs["demo_b_unknown_safe_state"] = {
        "safe_state_known": res_b.safe_state_resolution.known,
        "manual_review_required": res_b.manual_review_required,
        "selected_strategy": (
            res_b.selected_strategy.strategy_type.value if res_b.selected_strategy else None
        ),
        "reason_codes": [r.value for r in res_b.reason_codes],
    }

    # Demo C — Stale / incompatible deployment revision checkpoint
    ctx_c = ctx_spike.model_copy(update={"verified_patch_revision": "rev_newer_999"})
    res_c = engine.analyze(ctx_c, history=[cp5])
    outputs["demo_c_incompatible_checkpoint"] = {
        "safe_state_known": res_c.safe_state_resolution.known,
        "invalidations": [
            i.model_dump(mode="json") for i in res_c.safe_state_resolution.invalidated_checkpoints
        ],
    }

    # Demo D — Vulnerable legacy activation risk
    ctx_d = ctx_spike.model_copy(
        update={"current_legacy_feature_state": _feature_state("search_v1", True)}
    )
    res_d = engine.analyze(ctx_d, history=[])
    outputs["demo_d_legacy_activation_risk"] = {
        "executable_proposal": res_d.executable_proposal,
        "selected_strategy": (
            res_d.selected_strategy.strategy_type.value if res_d.selected_strategy else None
        ),
        "reason_codes": [r.value for r in res_d.reason_codes],
    }

    # Demo E — Unsupported percentage rollback (Boolean-only executor)
    ctx_e = ctx_spike.model_copy(
        update={
            "executor_capabilities": ExecutorCapabilities(
                supports_boolean=True,
                supports_targeting=False,
                fallback_verified=True,
                declared_fallback_behavior="disabled_search_response",
            )
        }
    )
    res_e = engine.analyze(ctx_e, history=[cp5])
    strat_a = next(
        c
        for c in res_e.candidate_strategies
        if c.strategy_type == RollbackStrategyType.RESTORE_VERIFIED_TARGETING
    )
    outputs["demo_e_unsupported_targeting"] = {
        "targeting_feasibility": strat_a.feasibility_status.value,
        "selected_strategy": (
            res_e.selected_strategy.strategy_type.value if res_e.selected_strategy else None
        ),
    }

    # Demo F — Altered approved configuration (approval tampering)
    tampered = appr_spike.model_copy(update={"proposal_hash": sha256_text("tampered")})
    res_f = validate_rollback_approval_binding(
        proposal=res_spike.proposal, approval=tampered, producer=human, reference_time=_NOW
    )
    outputs["demo_f_approval_tampering"] = {
        "allowed": res_f.allowed,
        "reason_code": res_f.reason_code,
    }

    # Demo G — External state drift
    res_g = revalidate_rollback_preconditions(
        proposal=res_spike.proposal,
        observed_feature_state=_feature_state("search_v2", False),
    )
    outputs["demo_g_external_state_drift"] = {
        "allowed": res_g.allowed,
        "reason_code": res_g.reason_code,
    }

    # Demo H — Failed readback
    res_h = reconcile_post_rollback_readback(
        proposal=res_spike.proposal,
        management_readback=_feature_state("search_v2", True),
        application_observed_exposure=25,
        legacy_feature_state=_feature_state("search_v1", False),
    )
    outputs["demo_h_failed_readback"] = {
        "matched": res_h.matched,
        "reason_codes": [r.value for r in res_h.reason_codes],
    }

    # Demo I — Post-rollback verification failure
    sec_fail = sec_post.model_copy(
        update={
            "execution_status": TestExecutionStatus.TEST_FAILED,
            "passed": False,
            "vulnerability_reproduced": True,
        }
    )
    res_i = verify_post_rollback(
        proposal=res_spike.proposal,
        receipt=rcpt_spike,
        readback=rb_check,
        security_verification=sec_fail,
    )
    outputs["demo_i_verification_failure"] = {
        "outcome": res_i.outcome.value,
        "recommended_state": res_i.recommended_incident_state.value,
    }

    # Demo J — Successful verified containment restoration (full disable -> CONTAINED)
    if res_a.proposal is None:
        raise RuntimeError("Missing proposal in Demo A/J.")
    rb_full = reconcile_post_rollback_readback(
        proposal=res_a.proposal,
        management_readback=_feature_state("search_v2", False),
        application_observed_enabled=False,
        legacy_feature_state=_feature_state("search_v1", False),
    )
    rcpt_full = rcpt_spike.model_copy(
        update={
            "proposal_id": res_a.proposal.proposal_id,
            "requested_state": False,
            "observed_state": False,
        }
    )
    res_j = verify_post_rollback(
        proposal=res_a.proposal,
        receipt=rcpt_full,
        readback=rb_full,
        security_verification=sec_post,
        expected_revision=_REV,
    )
    handoff = build_phase11_rollback_handoff(
        ctx=ctx_a,
        analysis=res_a,
        history=[cp5],
        receipt=rcpt_full,
        readback=rb_full,
        verification=res_j,
        final_incident_state=IncidentState.CONTAINED,
    )
    outputs["demo_j_verified_containment_restored"] = {
        "outcome": res_j.outcome.value,
        "full_containment_restored": res_j.full_containment_restored,
        "recommended_state": res_j.recommended_incident_state.value,
        "phase11_handoff_status": handoff.final_rollback_status,
    }

    return outputs


if __name__ == "__main__":
    print(json.dumps(run_all_rollback_demos(), indent=2, default=str))
