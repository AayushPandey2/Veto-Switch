"""Offline reproducible demonstrations for Phase 09 Progressive Rollout Intelligence."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_core.context import ProducerContext, RolloutStageRecord
from shared.enums import (
    ActorType,
    ApprovalStatus,
    DeploymentStatus,
    EvidenceProvenance,
    FeatureObservationStatus,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import (
    ApprovalDecision,
    DeploymentEvidence,
    FeatureState,
    IndividualTestOutcome,
    PatchTestResult,
    VerificationResult,
)
from shared.serialization import sha256_text

from remediation.adapters.fixture_telemetry import make_synthetic_snapshot
from remediation.release import (
    RecoveryEligibilityContext,
    assess_final_stage_completion,
    assign_cohort,
    build_stage_action_proposal,
    serialize_rollout_dashboard,
    validate_stage_proposal_approval,
)
from remediation.rollout_agent import DeterministicReleaseManager

_NOW = datetime(2026, 11, 28, 3, 0, 0, tzinfo=UTC)
_REV = "rev_patched_789012"


def _base_eligibility_ctx(*, deployed: bool = True) -> RecoveryEligibilityContext:
    ptr = PatchTestResult(
        test_run_id="trun_09_01",
        patch_id="pat_09_01",
        incident_id="inc_demo_09",
        tested_candidate_hash=sha256_text("diff_09"),
        expected_source_revision=_REV,
        tested_source_revision=_REV,
        overall_status=TestExecutionStatus.TEST_PASSED,
        started_at=_NOW - timedelta(minutes=25),
        completed_at=_NOW - timedelta(minutes=22),
        individual_outcomes=[
            IndividualTestOutcome(
                test_name="test_sqli_01",
                status=TestExecutionStatus.TEST_PASSED,
            ),
            IndividualTestOutcome(
                test_name="test_functional_01",
                status=TestExecutionStatus.TEST_PASSED,
            ),
        ],
        artifact_ids=["art_ptr_09"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    dep = (
        DeploymentEvidence(
            deployment_id="dep_09_01",
            environment="demo-staging",
            implementation_id="search_service_v2",
            feature_name="search_v2",
            source_revision=_REV,
            implementation_hash=sha256_text("built_search_v2"),
            deployed_at=_NOW - timedelta(minutes=20),
            deployment_status=DeploymentStatus.OBSERVED,
            addressable=True,
            evidence_ids=["art_dep_09"],
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        if deployed
        else None
    )
    sec_ver = VerificationResult(
        verification_id="ver_09_01",
        incident_id="inc_demo_09",
        test_id="test_sqli_01",
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_sec_09"],
        completed_at=_NOW - timedelta(minutes=15),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    return RecoveryEligibilityContext(
        incident_id="inc_demo_09",
        finding_id="fnd_09_01",
        active_patch_id="pat_09_01",
        candidate_diff_hash=sha256_text("diff_09"),
        verified_test_run_id="trun_09_01",
        verified_patched_revision=_REV,
        patch_test_result=ptr,
        deployment_evidence=dep,
        target_feature="search_v2",
        environment="demo-staging",
        current_feature_state=FeatureState(
            feature_id="feat_search_v2",
            environment="demo-staging",
            feature_name="search_v2",
            enabled=False,
            observation_status=FeatureObservationStatus.OBSERVED,
            observed_at=_NOW,
        ),
        legacy_feature_state=FeatureState(
            feature_id="feat_search_v1",
            environment="demo-staging",
            feature_name="search_v1",
            enabled=False,
            observation_status=FeatureObservationStatus.OBSERVED,
            observed_at=_NOW,
        ),
        reference_security_verification=sec_ver,
        evaluation_timestamp=_NOW,
        fixture_mode=True,
    )


def run_all_rollout_demos() -> dict[str, Any]:
    """Execute Phase 09 Demos A-I offline using deterministic fixtures."""
    mgr = DeterministicReleaseManager()
    ctx = _base_eligibility_ctx(deployed=True)
    gate, plan = mgr.plan_rollout(ctx)
    outputs: dict[str, Any] = {}

    # Demo A — Complete healthy 5 -> 25 -> 50 -> 100 recovery
    stage_records: list[RolloutStageRecord] = []
    stage_decisions: list[dict[str, Any]] = []
    for idx, stage in enumerate(plan.stages):
        snap = make_synthetic_snapshot(
            "healthy", stage_percentage=stage.exposure_percentage, observed_at=_NOW
        )
        bundle = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap,
            current_stage_id=stage.stage_id,
            observed_exposure=stage.exposure_percentage,
            observed_revision=_REV,
            evaluation_time=_NOW,
        )
        stage_decisions.append(
            serialize_rollout_dashboard(
                plan=plan,
                decision=bundle.decision,
                telemetry=snap,
                checks=bundle.guardrail_checks,
                next_proposal=bundle.next_stage_proposal,
            )
        )
        stage_records.append(
            RolloutStageRecord(
                stage_id=stage.stage_id,
                exposure_percentage=stage.exposure_percentage,
                target_revision=_REV,
                status="completed",
                approval_id=f"appr_stage_{idx}",
                operation_receipt_id=f"op_stage_{idx}",
                observed_exposure=stage.exposure_percentage,
                health_passed=True,
                security_verified=True,
            )
        )
    final_assess = assess_final_stage_completion(
        plan=plan,
        stage_records=stage_records,
        final_decision=mgr.evaluate_stage_full(
            plan=plan,
            telemetry=make_synthetic_snapshot("healthy", stage_percentage=100, observed_at=_NOW),
            current_stage_id=plan.stages[-1].stage_id,
            observed_exposure=100,
            observed_revision=_REV,
            evaluation_time=_NOW,
        ).decision,
        final_security_verification=ctx.reference_security_verification,
        legacy_feature_state=ctx.legacy_feature_state,
    )
    outputs["demo_a_complete_healthy_recovery"] = {
        "eligible": gate.eligible,
        "stages": stage_decisions,
        "final_assessment": final_assess.model_dump(mode="json"),
    }

    # Demo B — Insufficient telemetry (hold)
    snap_b = make_synthetic_snapshot("insufficient_requests", stage_percentage=5, observed_at=_NOW)
    outputs["demo_b_insufficient_telemetry"] = (
        mgr.evaluate_stage_full(plan=plan, telemetry=snap_b, evaluation_time=_NOW)
        .decision.model_dump(mode="json")
    )

    # Demo C — Error spike (rollback_proposed)
    snap_c = make_synthetic_snapshot("high_error_rate", stage_percentage=25, observed_at=_NOW)
    res_c = mgr.evaluate_stage_full(
        plan=plan, telemetry=snap_c, current_stage_id=plan.stages[1].stage_id, evaluation_time=_NOW
    )
    outputs["demo_c_error_spike"] = {
        "decision": res_c.decision.decision_type.value,
        "rollback_handoff": res_c.rollback_handoff.model_dump(mode="json")
        if res_c.rollback_handoff
        else None,
    }

    # Demo D — Latency degradation
    snap_d = make_synthetic_snapshot("high_p95_latency", stage_percentage=25, observed_at=_NOW)
    res_d = mgr.evaluate_stage_full(
        plan=plan, telemetry=snap_d, current_stage_id=plan.stages[1].stage_id, evaluation_time=_NOW
    )
    outputs["demo_d_latency_degradation"] = {
        "decision": res_d.decision.decision_type.value,
        "failed_guardrails": res_d.decision.failed_guardrails,
    }

    # Demo E — Missing deployment
    gate_e, _ = mgr.plan_rollout(_base_eligibility_ctx(deployed=False))
    outputs["demo_e_missing_deployment"] = gate_e.model_dump(mode="json")

    # Demo F — Targeting mismatch
    snap_f = make_synthetic_snapshot(
        "incorrect_observed_exposure", stage_percentage=5, observed_at=_NOW
    )
    outputs["demo_f_targeting_mismatch"] = (
        mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap_f,
            current_stage_id=plan.stages[0].stage_id,
            evaluation_time=_NOW,
        ).decision.model_dump(mode="json")
    )

    # Demo G — Cohort stability (nested 5 ⊂ 25 ⊂ 50 ⊂ 100)
    users = [f"user_{i}" for i in range(40)]
    c5 = {
        u
        for u in users
        if assign_cohort(cohort_namespace=plan.plan_id, identity=u, exposure_percentage=5).included
    }
    c25 = {
        u
        for u in users
        if assign_cohort(
            cohort_namespace=plan.plan_id, identity=u, exposure_percentage=25
        ).included
    }
    c50 = {
        u
        for u in users
        if assign_cohort(
            cohort_namespace=plan.plan_id, identity=u, exposure_percentage=50
        ).included
    }
    c100 = {
        u
        for u in users
        if assign_cohort(
            cohort_namespace=plan.plan_id, identity=u, exposure_percentage=100
        ).included
    }
    outputs["demo_g_cohort_stability"] = {
        "nested": c5 <= c25 <= c50 <= c100,
        "counts": {"5": len(c5), "25": len(c25), "50": len(c50), "100": len(c100)},
    }

    # Demo H — Approval tampering
    prop_h = build_stage_action_proposal(
        plan=plan, stage=plan.stages[1], created_at=_NOW
    )
    human = ProducerContext(
        producer_id="op_alice", actor_type=ActorType.HUMAN_OPERATOR, authenticated=True
    )
    appr_bad = ApprovalDecision(
        approval_id="appr_tampered",
        proposal_id=prop_h.proposal_id,
        proposal_hash=sha256_text("altered_targeting"),
        incident_id=plan.incident_id,
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_h",
        decided_at=_NOW,
        expires_at=_NOW + timedelta(minutes=15),
        authorization_context_ref="auth_h",
    )
    outputs["demo_h_approval_tampering"] = validate_stage_proposal_approval(
        proposal=prop_h, approval=appr_bad, producer=human, reference_time=_NOW
    ).model_dump(mode="json")

    # Demo I — Final-stage handling at 100%
    outputs["demo_i_final_stage"] = final_assess.model_dump(mode="json")

    return outputs


if __name__ == "__main__":
    print(json.dumps(run_all_rollout_demos(), indent=2, default=str))
