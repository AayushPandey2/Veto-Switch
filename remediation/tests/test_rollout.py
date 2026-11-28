"""Tests for Phase 09 Progressive Rollout Intelligence."""

from __future__ import annotations

from datetime import timedelta

from agent_core.context import ProducerContext
from remediation.adapters.fixture_telemetry import make_synthetic_snapshot
from remediation.evaluations.rollout_evaluator import run_rollout_evaluation
from remediation.policies import wilson_confidence_interval
from remediation.release import (
    RecoveryEligibilityStatus,
    assign_cohort,
    build_stage_action_proposal,
    validate_stage_proposal_approval,
)
from remediation.rollout_agent import (
    DeterministicReleaseManager,
    build_rollout_plan,
    evaluate_rollout_stage,
)
from remediation.rollout_demos import _NOW, _REV, _base_eligibility_ctx, run_all_rollout_demos
from shared.enums import (
    ActorType,
    ApprovalStatus,
    RolloutDecisionType,
)
from shared.schemas import ApprovalDecision
from shared.serialization import sha256_text


def test_roadmap_compat_build_and_evaluate_rollout() -> None:
    plan_dict = build_rollout_plan("inc_compat_09", {"revision": _REV})
    assert [s["exposure_percentage"] for s in plan_dict["stages"]] == [5, 25, 50, 100]
    dec = evaluate_rollout_stage(
        plan_dict,
        {
            "request_count": 200,
            "failed_request_count": 2,
            "baseline_error_rate": 0.005,
            "baseline_p95_latency_ms": 40.0,
            "p95_latency_ms": 44.0,
            "security_regression_passed": True,
        },
        {"observed_exposure": 5},
    )
    assert dec["decision_type"] == "advance"


def test_deterministic_nested_cohorts_and_boundaries() -> None:
    assert (
        assign_cohort(cohort_namespace="ns1", identity=None, exposure_percentage=100).included
        is False
    )
    assert (
        assign_cohort(cohort_namespace="ns1", identity="u1", exposure_percentage=0).included
        is False
    )
    assert (
        assign_cohort(cohort_namespace="ns1", identity="u1", exposure_percentage=100).included
        is True
    )

    users = [f"user_{i}" for i in range(100)]
    c5 = {
        u
        for u in users
        if assign_cohort(cohort_namespace="plan_x", identity=u, exposure_percentage=5).included
    }
    c25 = {
        u
        for u in users
        if assign_cohort(cohort_namespace="plan_x", identity=u, exposure_percentage=25).included
    }
    c50 = {
        u
        for u in users
        if assign_cohort(cohort_namespace="plan_x", identity=u, exposure_percentage=50).included
    }
    assert c5 <= c25 <= c50


def test_eligibility_gate_and_guardrail_precedence() -> None:
    mgr = DeterministicReleaseManager()
    ctx = _base_eligibility_ctx(deployed=True)
    gate, plan = mgr.plan_rollout(ctx)
    assert gate.eligible is True
    assert gate.status == RecoveryEligibilityStatus.ELIGIBLE_FOR_STAGE_PROPOSAL

    # Security failure overrides healthy operational metrics -> rollback_proposed
    sec_fail = make_synthetic_snapshot(
        "confirmed_security_regression", stage_percentage=25, observed_at=_NOW
    )
    res_sec = mgr.evaluate_stage_full(
        plan=plan,
        telemetry=sec_fail,
        current_stage_id=plan.stages[1].stage_id,
        observed_revision=_REV,
        evaluation_time=_NOW,
    )
    assert res_sec.decision.decision_type == RolloutDecisionType.ROLLBACK_PROPOSED
    assert res_sec.rollback_handoff is not None

    # Unknown security -> hold
    sec_unk = make_synthetic_snapshot(
        "missing_security_result", stage_percentage=5, observed_at=_NOW
    )
    res_unk = mgr.evaluate_stage_full(
        plan=plan,
        telemetry=sec_unk,
        current_stage_id=plan.stages[0].stage_id,
        observed_revision=_REV,
        evaluation_time=_NOW,
    )
    assert res_unk.decision.decision_type == RolloutDecisionType.HOLD

    # Synthetic in live mode -> hold
    healthy = make_synthetic_snapshot("healthy", stage_percentage=5, observed_at=_NOW)
    res_live = mgr.evaluate_stage_full(
        plan=plan,
        telemetry=healthy,
        current_stage_id=plan.stages[0].stage_id,
        observed_revision=_REV,
        live_mode=True,
        evaluation_time=_NOW,
    )
    assert res_live.decision.decision_type == RolloutDecisionType.HOLD


def test_stage_proposal_approval_and_wilson_ci() -> None:
    mgr = DeterministicReleaseManager()
    _, plan = mgr.plan_rollout(_base_eligibility_ctx())
    prop = build_stage_action_proposal(plan=plan, stage=plan.stages[1], created_at=_NOW)
    human = ProducerContext(
        producer_id="op_alice", actor_type=ActorType.HUMAN_OPERATOR, authenticated=True
    )
    appr = ApprovalDecision(
        approval_id="appr_s2",
        proposal_id=prop.proposal_id,
        proposal_hash=prop.proposal_hash or "",
        incident_id=plan.incident_id,
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="n_s2",
        decided_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
        authorization_context_ref="auth_s2",
    )
    assert validate_stage_proposal_approval(
        proposal=prop, approval=appr, producer=human, reference_time=_NOW
    ).allowed
    assert not validate_stage_proposal_approval(
        proposal=prop,
        approval=appr.model_copy(update={"proposal_hash": sha256_text("tampered")}),
        producer=human,
        reference_time=_NOW,
    ).allowed
    lo, hi = wilson_confidence_interval(0, 100)
    assert 0.0 <= lo < hi <= 1.0


def test_rollout_demos_and_evaluator_pass() -> None:
    demos = run_all_rollout_demos()
    assert (
        demos["demo_a_complete_healthy_recovery"]["final_assessment"]["ready_for_recovered"]
        is True
    )
    assert demos["demo_g_cohort_stability"]["nested"] is True
    assert demos["demo_h_approval_tampering"]["allowed"] is False

    report = run_rollout_evaluation(write_reports=False)
    assert report["passed_cases"] == report["total_cases"]
    assert report["unsafe_advance_count"] == 0
    assert report["unauthorized_action_count"] == 0
    assert report["false_recovery_claim_count"] == 0
