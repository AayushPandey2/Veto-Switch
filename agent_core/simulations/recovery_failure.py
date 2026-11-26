"""Synthetic Simulations E (Failed Patch) & F (Failed Rollout / Rollback Proposed)."""

from __future__ import annotations

from datetime import timedelta

from shared.config import load_rollout_policy
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    DeploymentStatus,
    EventType,
    EvidenceProvenance,
    IncidentState,
    OperationOutcome,
    PatchOrigin,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.identifiers import (
    generate_approval_id,
    generate_deployment_id,
    generate_operation_id,
    generate_patch_id,
    generate_rollback_id,
    generate_rollout_plan_id,
    generate_rollout_stage_id,
    generate_test_run_id,
    generate_verification_id,
)
from shared.schemas import (
    ApprovalDecision,
    DeploymentEvidence,
    IndividualTestOutcome,
    LatencyStats,
    MetricSnapshot,
    OperationReceipt,
    PatchProposal,
    PatchTestResult,
    RollbackProposal,
    RolloutGuardrailConfig,
    RolloutPlan,
    RolloutStage,
    VerificationResult,
)
from shared.serialization import sha256_text

from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.idempotency import build_operation_idempotency_key
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.simulations.rejected_incident import _setup_awaiting_approval
from agent_core.simulations.successful_incident import SimulationSummary, seed_artifact


async def _reach_contained() -> tuple[
    IncidentOrchestrator,
    InMemoryOrchestrationRepository,
    FixedClock,
    str,
    str,
]:
    (
        orchestrator,
        repo,
        clock,
        inc_id,
        corr_id,
        await_evt_id,
        fs,
        proposal,
    ) = await _setup_awaiting_approval()
    p_human = ProducerContext(
        producer_id="secops_lead",
        actor_type=ActorType.HUMAN_OPERATOR,
        authenticated=True,
        trusted_channel="sim_ui",
        provenance_mode="fixture",
    )
    p_exec = ProducerContext(
        producer_id="fixture_executor",
        actor_type=ActorType.PLATFORM_EXECUTOR,
        authenticated=True,
        trusted_channel="sim_exec",
        provenance_mode="fixture",
    )
    p_ver = ProducerContext(
        producer_id="sim_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    appr = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        proposal_hash=proposal.proposal_hash,  # type: ignore[attr-defined]
        incident_id=inc_id,
        actor_id="secops_lead",
        decision=ApprovalStatus.APPROVED,
        decided_at=clock.now(),
        expires_at=proposal.expires_at,  # type: ignore[attr-defined]
        authorization_context_ref="authctx_cont_001",
        nonce="nonce_cont_001",
    )
    evt_appr = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.APPROVAL_GRANTED,
        actor="secops_lead",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=7,
        correlation_id=corr_id,
        causation_id=await_evt_id,
        evidence_ids=list(proposal.evidence_ids),  # type: ignore[attr-defined]
        timestamp_utc=clock.now(),
    )
    await orchestrator.process_event(
        evt_appr,
        p_human,
        TransitionContext(
            producer_context=p_human,
            clock=clock,
            fixture_mode=True,
            active_proposal=proposal,  # type: ignore[arg-type]
            approval_decision=appr,
            feature_state=fs,
        ),
    )
    rec_art = await seed_artifact(
        repo, incident_id=inc_id, artifact_type=ArtifactType.OPERATION_RECEIPT, content_text="ok"
    )
    receipt = OperationReceipt(
        operation_id=generate_operation_id(),
        incident_id=inc_id,
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        approval_id=appr.approval_id,
        environment=proposal.environment,  # type: ignore[attr-defined]
        target_feature="search_v1",
        requested_state=False,
        observed_state=False,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key=build_operation_idempotency_key(
            incident_id=inc_id,
            proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
            approval_id=appr.approval_id,
            environment=proposal.environment,  # type: ignore[attr-defined]
            target_feature="search_v1",
            desired_enabled=False,
        ),
        executed_at=clock.now() + timedelta(seconds=2),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        evidence_ids=[rec_art],
    )
    evt_exec = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.FLAG_UPDATE_SUCCESS,
        actor="fixture_executor",
        actor_type=ActorType.PLATFORM_EXECUTOR,
        sequence_number=8,
        correlation_id=corr_id,
        causation_id=evt_appr.event_id,
        evidence_ids=[rec_art],
        timestamp_utc=clock.now() + timedelta(seconds=2),
    )
    await orchestrator.process_event(
        evt_exec,
        p_exec,
        TransitionContext(
            producer_context=p_exec, clock=clock, fixture_mode=True, operation_receipt=receipt
        ),
    )
    reg_art = await seed_artifact(
        repo, incident_id=inc_id, artifact_type=ArtifactType.REGRESSION_LOG, content_text="blocked"
    )
    fs_off = fs.model_copy(
        update={"enabled": False, "observed_at": clock.now() + timedelta(seconds=4)}
    )
    vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=inc_id,
        test_id="sqli_after",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        observed_feature_state=False,
        expected_revision="rev_demo_001",
        tested_revision="rev_demo_001",
        artifact_ids=[reg_art],
        started_at=clock.now() + timedelta(seconds=3),
        completed_at=clock.now() + timedelta(seconds=5),
        exit_code=0,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.CONTAINMENT_CONFIRMED,
            actor="sim_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=9,
            correlation_id=corr_id,
            causation_id=evt_exec.event_id,
            evidence_ids=[reg_art],
            timestamp_utc=clock.now() + timedelta(seconds=5),
        ),
        p_ver,
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            verification_result=vr,
            feature_state=fs_off,
            functional_smoke_passed=True,
        ),
    )
    return orchestrator, repo, clock, inc_id, corr_id


async def run_patch_failure_simulation() -> SimulationSummary:
    """Simulation E: Security passes but functional test fails -> PATCH_FAILED."""
    orchestrator, _repo, clock, inc_id, corr_id = await _reach_contained()
    p_eng = ProducerContext(
        producer_id="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    p_ver = ProducerContext(
        producer_id="sim_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.PATCH_REQUESTED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=10,
            correlation_id=corr_id,
            timestamp_utc=clock.now() + timedelta(seconds=10),
        ),
        p_eng,
        TransitionContext(producer_context=p_eng, clock=clock, fixture_mode=True),
    )
    res_fail = await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.PATCH_TEST_FAILED,
            actor="sim_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=11,
            correlation_id=corr_id,
            timestamp_utc=clock.now() + timedelta(seconds=15),
            payload={"reason": "Security test passed but functional search pagination failed."},
        ),
        p_ver,
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            patch_test_result=PatchTestResult(
                test_run_id=generate_test_run_id(),
                patch_id=generate_patch_id(),
                incident_id=inc_id,
                expected_source_revision="rev_demo_001",
                tested_source_revision="rev_demo_001",
                tested_candidate_hash="a" * 64,
                individual_outcomes=[
                    IndividualTestOutcome(
                        test_name="sec_sqli",
                        category="security",
                        status=TestExecutionStatus.TEST_PASSED,
                    ),
                    IndividualTestOutcome(
                        test_name="func_search",
                        category="functional",
                        status=TestExecutionStatus.TEST_FAILED,
                    ),
                ],
                overall_status=TestExecutionStatus.TEST_FAILED,
                started_at=clock.now() + timedelta(seconds=11),
                completed_at=clock.now() + timedelta(seconds=14),
                provenance=EvidenceProvenance.REFERENCE_FIXTURE,
            ),
        ),
    )
    assert res_fail.accepted and res_fail.current_state == IncidentState.PATCH_FAILED
    events = await orchestrator.get_incident_events(inc_id)
    replayed = await orchestrator.replay_incident(inc_id)
    return SimulationSummary(
        name="Simulation E: Failed Patch (Functional Regression)",
        incident_id=inc_id,
        final_state=IncidentState.PATCH_FAILED,
        incident_version=res_fail.incident_version,
        event_count=len(events),
        pending_requests_count=0,
        replay_matched=(replayed.current_state == IncidentState.PATCH_FAILED),
        notes="Patch blocked in PATCH_FAILED; recovery rollout cannot begin.",
    )


async def run_rollout_failure_simulation() -> SimulationSummary:
    """Simulation F: Synthetic health guardrail breach proposes rollback without auto-execution."""
    orchestrator, repo, clock, inc_id, corr_id = await _reach_contained()
    policy = load_rollout_policy()
    p_eng = ProducerContext(
        producer_id="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    p_ver = ProducerContext(
        producer_id="sim_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.PATCH_REQUESTED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=10,
            correlation_id=corr_id,
            timestamp_utc=clock.now() + timedelta(seconds=10),
        ),
        p_eng,
        TransitionContext(producer_context=p_eng, clock=clock, fixture_mode=True),
    )
    diff_text = "--- a/app/search.py\n+++ b/app/search.py\n-bad\n+good\n"
    patch_hash = sha256_text(diff_text)
    patch_art = await seed_artifact(
        repo, incident_id=inc_id, artifact_type=ArtifactType.PATCH_DIFF, content_text=diff_text
    )
    patch_id = generate_patch_id()
    patch_prop = PatchProposal(
        patch_id=patch_id,
        incident_id=inc_id,
        finding_id="fnd_0001",
        source_revision="rev_demo_001",
        candidate_artifact_id=patch_art,
        candidate_content_hash=patch_hash,
        unified_diff=diff_text,
        allowed_files=["app/search.py"],
        touched_files=["app/search.py"],
        technical_rationale="Fix SQLi",
        required_tests=["sec", "func"],
        patch_origin=PatchOrigin.REFERENCE_FIXTURE,
    )
    patch_test_art = await seed_artifact(
        repo, incident_id=inc_id, artifact_type=ArtifactType.PATCH_TEST_LOG, content_text="ok"
    )
    patch_res = PatchTestResult(
        test_run_id=generate_test_run_id(),
        patch_id=patch_id,
        incident_id=inc_id,
        expected_source_revision="rev_demo_001",
        tested_source_revision="rev_demo_001",
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
        artifact_ids=[patch_test_art],
        started_at=clock.now() + timedelta(seconds=12),
        completed_at=clock.now() + timedelta(seconds=14),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.PATCH_TEST_PASSED,
            actor="sim_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=11,
            correlation_id=corr_id,
            evidence_ids=[patch_test_art],
            timestamp_utc=clock.now() + timedelta(seconds=15),
        ),
        p_ver,
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            patch_proposal=patch_prop,
            patch_test_result=patch_res,
        ),
    )

    dep_art = await seed_artifact(
        repo,
        incident_id=inc_id,
        artifact_type=ArtifactType.DEPLOYMENT_MANIFEST,
        content_text="rev_patched",
    )
    dep = DeploymentEvidence(
        deployment_id=generate_deployment_id(),
        environment="demo-staging",
        implementation_id="search_v2",
        feature_name="search_v2",
        source_revision="rev_patched",
        implementation_hash=patch_hash,
        deployed_at=clock.now() + timedelta(seconds=16),
        deployment_status=DeploymentStatus.OBSERVED,
        addressable=True,
        evidence_ids=[dep_art],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    gr = RolloutGuardrailConfig(
        max_error_rate=policy.guardrails.max_error_rate,
        max_error_rate_increase_pp=policy.guardrails.max_error_rate_increase_pp,
        max_p95_latency_increase_percent=policy.guardrails.max_p95_latency_increase_percent,
    )
    stages = [
        RolloutStage(
            stage_id=generate_rollout_stage_id(),
            exposure_percentage=pct,
            required_metrics=["error_rate"],
            minimum_observation_window_seconds=30,
            minimum_request_count=100,
            guardrails=gr,
        )
        for pct in policy.stages_percent
    ]
    plan = RolloutPlan(
        plan_id=generate_rollout_plan_id(),
        incident_id=inc_id,
        target_feature="search_v2",
        environment="demo-staging",
        target_implementation_revision="rev_patched",
        stages=stages,
        guardrails=gr,
        evidence_ids=[dep_art],
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.ROLLOUT_PLAN_CREATED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=12,
            correlation_id=corr_id,
            evidence_ids=[dep_art],
            timestamp_utc=clock.now() + timedelta(seconds=17),
        ),
        p_eng,
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            patch_proposal=patch_prop,
            patch_test_result=patch_res,
            deployment_evidence=dep,
            rollout_plan=plan,
        ),
    )

    tele_art = await seed_artifact(
        repo,
        incident_id=inc_id,
        artifact_type=ArtifactType.TELEMETRY_SNAPSHOT,
        content_text="error_rate=0.09",
    )
    bad_snap = MetricSnapshot(
        snapshot_id="met_sim_bad_01",
        incident_id=inc_id,
        environment="demo-staging",
        feature_id="search_v2",
        observation_window_seconds=45,
        request_count=200,
        failed_request_count=18,
        error_rate=0.09,
        latency_ms=LatencyStats(p50_ms=25.0, p95_ms=110.0, p99_ms=180.0),
        baseline_error_rate=0.005,
        baseline_p95_latency_ms=35.0,
        security_regression_passed=True,
        observed_rollout_stage_percentage=5,
        provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        evidence_ids=[tele_art],
    )
    rb = RollbackProposal(
        proposal_id=generate_rollback_id(),
        incident_id=inc_id,
        target_environment="demo-staging",
        target_feature="search_v2",
        current_state=True,
        last_verified_safe_state_known=True,
        last_verified_safe_state=False,
        proposed_state=False,
        triggering_evidence_ids=[tele_art],
        rollback_rationale="Synthetic error rate 9.0% exceeded 2.0% threshold.",
        safety_limitations=["Do not fall back to unpatched search_v1."],
        manual_review_required=True,
        approval_required=True,
    )
    res_rb = await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.ROLLBACK_PROPOSED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=13,
            correlation_id=corr_id,
            evidence_ids=[tele_art],
            timestamp_utc=clock.now() + timedelta(seconds=20),
        ),
        p_eng,
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            metric_snapshot=bad_snap,
            rollback_proposal=rb,
        ),
    )
    assert res_rb.accepted and res_rb.current_state == IncidentState.ROLLBACK_PROPOSED
    pending = await repo.list_pending_requests(inc_id)
    rb_execs = [r for r in pending if r.request_type == "platform_rollback_execution_request"]
    assert len(rb_execs) == 0

    events = await orchestrator.get_incident_events(inc_id)
    replayed = await orchestrator.replay_incident(inc_id)
    return SimulationSummary(
        name="Simulation F: Failed Rollout -> Rollback Proposed",
        incident_id=inc_id,
        final_state=IncidentState.ROLLBACK_PROPOSED,
        incident_version=res_rb.incident_version,
        event_count=len(events),
        pending_requests_count=len(rb_execs),
        replay_matched=(replayed.current_state == IncidentState.ROLLBACK_PROPOSED),
        notes=(
            "Synthetic telemetry breach routed to ROLLBACK_PROPOSED "
            "with 0 unapproved executions."
        ),
    )
