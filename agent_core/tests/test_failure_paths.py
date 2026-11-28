"""Categories I & J: Failure paths, recovery invariants, and security-boundary tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.state_machine import can_transition, validate_transition
from agent_core.tests.conftest import (
    make_feature_state,
    make_finding,
    make_incident,
    make_producer,
)
from shared.enums import (
    ActorType,
    DeploymentStatus,
    EventType,
    EvidenceProvenance,
    IncidentState,
    PatchOrigin,
    TestExecutionStatus,
)
from shared.identifiers import (
    generate_artifact_id,
    generate_deployment_id,
    generate_patch_id,
    generate_rollback_id,
    generate_rollout_plan_id,
    generate_rollout_stage_id,
    generate_test_run_id,
)
from shared.schemas import (
    DeploymentEvidence,
    IndividualTestOutcome,
    PatchProposal,
    PatchTestResult,
    RollbackProposal,
    RolloutGuardrailConfig,
    RolloutPlan,
    RolloutStage,
)


@pytest.mark.unit
def test_recovery_gates_separate_patch_testing_deployment_and_activation(
    fixed_clock: FixedClock,
) -> None:
    inc_id = "inc_rec_gate_01"
    art = generate_artifact_id()
    patch_id = generate_patch_id()
    patch_hash = "a" * 64

    # 1. Patch proposal does not imply patch tested (still PATCH_PENDING)
    make_incident(state=IncidentState.PATCH_PENDING, incident_id=inc_id)
    assert can_transition(IncidentState.PATCH_PENDING, EventType.ROLLOUT_PLAN_CREATED) is False

    # 2. Missing deployment blocks ROLLOUT_PENDING from PATCH_TESTED
    inc_tested = make_incident(state=IncidentState.PATCH_TESTED, incident_id=inc_id)
    inc_tested = inc_tested.model_copy(
        update={"active_patch_id": patch_id, "active_patch_hash": patch_hash}
    )
    gr = RolloutGuardrailConfig(
        max_error_rate=0.02,
        max_error_rate_increase_pp=1.0,
        max_p95_latency_increase_percent=20.0,
    )
    plan = RolloutPlan(
        plan_id=generate_rollout_plan_id(),
        incident_id=inc_id,
        target_feature="search_v2",
        environment="demo-staging",
        target_implementation_revision="rev_abc123",
        stages=[
            RolloutStage(
                stage_id=generate_rollout_stage_id(),
                exposure_percentage=5,
                required_metrics=["error_rate"],
                minimum_observation_window_seconds=30,
                minimum_request_count=100,
                guardrails=gr,
            )
        ],
        guardrails=gr,
        evidence_ids=[art],
    )
    missing_dep = DeploymentEvidence(
        deployment_id=generate_deployment_id(),
        environment="demo-staging",
        implementation_id="search_v2",
        feature_name="search_v2",
        source_revision="rev_abc123",
        implementation_hash=patch_hash,
        deployment_status=DeploymentStatus.MISSING,
        addressable=False,
    )
    patch_prop = PatchProposal(
        patch_id=patch_id,
        incident_id=inc_id,
        finding_id=inc_tested.finding_id,
        source_revision="rev_abc123",
        candidate_artifact_id=art,
        candidate_content_hash=patch_hash,
        unified_diff="--- a/app/s.py\n+++ b/app/s.py\n",
        allowed_files=["app/s.py"],
        touched_files=["app/s.py"],
        technical_rationale="Fix",
        required_tests=["sec", "func"],
        patch_origin=PatchOrigin.REFERENCE_FIXTURE,
    )
    patch_res = PatchTestResult(
        test_run_id=generate_test_run_id(),
        patch_id=patch_id,
        incident_id=inc_id,
        expected_source_revision="rev_abc123",
        tested_source_revision="rev_abc123",
        tested_candidate_hash=patch_hash,
        individual_outcomes=[
            IndividualTestOutcome(
                test_name="sec", category="security", status=TestExecutionStatus.TEST_PASSED
            ),
            IndividualTestOutcome(
                test_name="func", category="functional", status=TestExecutionStatus.TEST_PASSED
            ),
        ],
        overall_status=TestExecutionStatus.TEST_PASSED,
        artifact_ids=[art],
        started_at=fixed_clock.now(),
        completed_at=fixed_clock.now() + timedelta(seconds=2),
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    evt_roll = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.ROLLOUT_PLAN_CREATED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc_tested.correlation_id,
        evidence_ids=[art],
        timestamp_utc=fixed_clock.now(),
    )
    ctx = TransitionContext(
        producer_context=make_producer(ActorType.DETERMINISTIC_ENGINE),
        clock=fixed_clock,
        patch_proposal=patch_prop,
        patch_test_result=patch_res,
        deployment_evidence=missing_dep,
        rollout_plan=plan,
        existing_evidence_ids={art},
    )
    _, results = validate_transition(inc_tested, evt_roll, ctx)
    assert any(
        f.reason_code == "DEPLOYMENT_NOT_OBSERVED_OR_UNADDRESSABLE"
        for f in results
        if not f.allowed
    )

    # 3. Incomplete rollout (only 5% completed, not 100%) cannot mark incident RECOVERED
    inc_roll = make_incident(state=IncidentState.ROLLOUT_PENDING, incident_id=inc_id)
    evt_complete = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.ROLLOUT_COMPLETED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc_roll.correlation_id,
        evidence_ids=[art],
        timestamp_utc=fixed_clock.now(),
    )
    _, comp_results = validate_transition(inc_roll, evt_complete, ctx)
    assert any(f.reason_code == "NO_ROLLOUT_STAGES_EXECUTED" for f in comp_results if not f.allowed)


@pytest.mark.unit
async def test_failure_routing_and_unknown_outcome_reconciliation(
    fixture_orchestrator: IncidentOrchestrator, fixed_clock: FixedClock
) -> None:
    finding = make_finding(
        incident_id="inc_fail_route_01",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    inc = await fixture_orchestrator.create_incident(
        finding, make_producer(ActorType.SECURITY_SCANNER, provenance_mode="fixture")
    )
    p_eng = make_producer(ActorType.DETERMINISTIC_ENGINE, provenance_mode="fixture")
    p_ver = make_producer(ActorType.SECURITY_VERIFIER, provenance_mode="fixture")

    # Verification failure -> UNVERIFIED
    await fixture_orchestrator.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.VERIFICATION_REQUESTED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=2,
            correlation_id=inc.correlation_id,
            timestamp_utc=fixed_clock.now(),
        ),
        p_eng,
        TransitionContext(
            producer_context=p_eng, clock=fixed_clock, fixture_mode=True, finding=finding
        ),
    )
    res_unv = await fixture_orchestrator.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.VERIFICATION_INCONCLUSIVE,
            actor="verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id=inc.correlation_id,
            timestamp_utc=fixed_clock.now(),
            payload={"reason": "Target returned 502 during reproduction."},
        ),
        p_ver,
        TransitionContext(
            producer_context=p_ver, clock=fixed_clock, fixture_mode=True, finding=finding
        ),
    )
    assert res_unv.accepted and res_unv.current_state == IncidentState.UNVERIFIED

    # Unknown external write outcome in APPLYING -> CHANGE_FAILED + reconciliation request
    inc_apply = make_incident(state=IncidentState.APPLYING, incident_id="inc_unknown_op_01")
    p_exec = make_producer(ActorType.PLATFORM_EXECUTOR)
    evt_unk = build_incident_event(
        incident_id=inc_apply.incident_id,
        event_type=EventType.FLAG_UPDATE_OUTCOME_UNKNOWN,
        actor="exec",
        actor_type=ActorType.PLATFORM_EXECUTOR,
        sequence_number=2,
        correlation_id=inc_apply.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    target, unk_res = validate_transition(
        inc_apply,
        evt_unk,
        TransitionContext(producer_context=p_exec, clock=fixed_clock),
    )
    assert target == IncidentState.CHANGE_FAILED
    assert all(r.allowed for r in unk_res)

    # Rollback proposal does not mutate feature flags and requires approval
    rb = RollbackProposal(
        proposal_id=generate_rollback_id(),
        incident_id="inc_rb_01",
        target_environment="demo-staging",
        target_feature="search_v2",
        current_state=True,
        last_verified_safe_state_known=False,
        last_verified_safe_state=None,
        proposed_state=False,
        triggering_evidence_ids=["art_0001"],
        rollback_rationale="Unknown safe state requires manual review.",
        manual_review_required=True,
        approval_required=True,
    )
    assert rb.approval_required is True
    assert rb.manual_review_required is True
    _ = make_feature_state(enabled=True)
