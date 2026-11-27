"""Tests for Phase 10 RollbackIntelligenceEngine, triggers, feasibility, and legacy protection."""

from __future__ import annotations

from datetime import timedelta

from remediation.recovery import (
    ExecutorCapabilities,
    RollbackContext,
    build_phase11_rollback_handoff,
    serialize_rollback_dashboard,
    validate_rollback_trigger,
)
from remediation.rollback import RollbackIntelligenceEngine, propose_rollback
from remediation.rollback_demos import (
    _NOW,
    _REV,
    _base_deployment,
    _degraded_25pct_decision,
    _feature_state,
    _safe_checkpoint_5pct,
)
from shared.enums import (
    CoverageStatus,
    EvidenceProvenance,
    RollbackActionType,
    RollbackFeasibilityStatus,
    RollbackReasonCode,
    RollbackStrategyType,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import (
    CoverageFinding,
    RolloutDecision,
    VerificationResult,
)


def test_propose_rollback_ignores_caller_last_good_state() -> None:
    res = propose_rollback(
        "inc_compat_01",
        {"search_v1": True, "exposure": 100},
        "Synthetic error spike",
    )
    assert res["last_verified_safe_state_known"] is False
    assert res["last_verified_safe_state"] is None
    assert res["manual_review_required"] is True
    assert res["approval_required"] is True
    assert res["execution_authorized"] is False
    assert res["caller_last_good_state_ignored"] is True


def test_operational_degradation_selects_verified_targeting_rollback() -> None:
    engine = RollbackIntelligenceEngine()
    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    ctx = RollbackContext(
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
        ),
        evaluation_timestamp=_NOW,
    )
    result = engine.analyze(ctx, history=[cp5])
    assert result.selected_strategy is not None
    assert (
        result.selected_strategy.strategy_type
        == RollbackStrategyType.RESTORE_VERIFIED_TARGETING
    )
    assert result.executable_proposal is True
    assert result.proposal is not None
    assert result.proposal.action_type == RollbackActionType.TARGETING_CONFIGURATION
    assert result.proposal.execution_authorized is False
    dash = serialize_rollback_dashboard(ctx=ctx, analysis=result)
    assert dash["current_observed_exposure"] == 25
    assert dash["last_verified_safe_exposure"] == 5
    handoff = build_phase11_rollback_handoff(ctx=ctx, analysis=result, history=[cp5])
    assert handoff.proposal_hash == result.proposal.proposal_hash


def test_security_regression_never_selects_partial_targeting() -> None:
    engine = RollbackIntelligenceEngine()
    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    sec_fail = VerificationResult(
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
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        current_observed_exposure=25,
        current_observed_feature_state=_feature_state("search_v2", True),
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision=_REV,
        deployment_evidence=_base_deployment(),
        rollout_decision=dec25,
        triggering_telemetry=met25,
        security_regression_result=sec_fail,
        current_legacy_feature_state=_feature_state("search_v1", False),
        executor_capabilities=ExecutorCapabilities(
            supports_boolean=True,
            supports_targeting=True,
            declared_fallback_behavior="disabled_search_response",
            fallback_verified=True,
        ),
        evaluation_timestamp=_NOW,
    )
    result = engine.analyze(ctx, history=[cp5])
    assert result.selected_strategy is not None
    assert result.selected_strategy.strategy_type != RollbackStrategyType.RESTORE_VERIFIED_TARGETING
    assert result.proposal is not None
    assert result.proposal.proposed_state is False
    assert RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED in result.reason_codes


def test_legacy_exposure_risk_blocks_disable_strategy() -> None:
    engine = RollbackIntelligenceEngine()
    dec25, met25 = _degraded_25pct_decision()
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        current_observed_exposure=25,
        current_observed_feature_state=_feature_state("search_v2", True),
        target_feature="search_v2",
        environment="demo-staging",
        rollout_decision=dec25,
        triggering_telemetry=met25,
        current_legacy_feature_state=_feature_state("search_v1", True),
        executor_capabilities=ExecutorCapabilities(
            supports_boolean=True, fallback_verified=True, declared_fallback_behavior="disabled"
        ),
        evaluation_timestamp=_NOW,
    )
    result = engine.analyze(ctx, history=[])
    assert result.executable_proposal is False
    assert RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED in result.reason_codes


def test_missing_evidence_triggers_hold_not_fabricated_failure() -> None:
    dec = RolloutDecision(
        decision_id="rdec_hold",
        plan_id="rplan_demo_10",
        incident_id="inc_demo_10",
        current_stage_id="stage_5pct",
        decision_type=RolloutDecisionType.HOLD,
        evaluated_guardrails=["max_error_rate"],
        missing_evidence=["telemetry_snapshot"],
        explanation="Telemetry missing.",
    )
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        target_feature="search_v2",
        environment="demo-staging",
        rollout_decision=dec,
        evaluation_timestamp=_NOW,
    )
    trig = validate_rollback_trigger(ctx)
    assert trig.valid is False
    assert trig.is_missing_evidence_hold is True
    assert RollbackReasonCode.TRIGGER_EVIDENCE_MISSING in trig.reason_codes


def test_boolean_only_executor_marks_targeting_unsupported() -> None:
    engine = RollbackIntelligenceEngine()
    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        current_observed_exposure=25,
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
            supports_targeting=False,
            fallback_verified=True,
            declared_fallback_behavior="disabled_search_response",
        ),
        evaluation_timestamp=_NOW + timedelta(seconds=1),
    )
    result = engine.analyze(ctx, history=[cp5])
    strat_a = next(
        c
        for c in result.candidate_strategies
        if c.strategy_type == RollbackStrategyType.RESTORE_VERIFIED_TARGETING
    )
    assert strat_a.feasibility_status == RollbackFeasibilityStatus.UNSUPPORTED
    assert RollbackReasonCode.TARGETING_EXECUTOR_UNAVAILABLE in strat_a.reason_codes


def test_coverage_gap_blocks_unsafe_disable() -> None:
    engine = RollbackIntelligenceEngine()
    dec25, met25 = _degraded_25pct_decision()
    cov = CoverageFinding(
        coverage_finding_id="cov_gap",
        route="/v1/search",
        component="search_v1",
        coverage_status=CoverageStatus.UNPROTECTED,
        explanation="Unprotected alternate route.",
        recommended_action="Add flag.",
        evidence_ids=["art_cov"],
    )
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        current_observed_feature_state=_feature_state("search_v2", True),
        target_feature="search_v2",
        environment="demo-staging",
        rollout_decision=dec25,
        triggering_telemetry=met25,
        current_legacy_feature_state=_feature_state("search_v1", False),
        coverage_findings=[cov],
        evaluation_timestamp=_NOW,
    )
    result = engine.analyze(ctx, history=[])
    assert result.executable_proposal is False
