"""Synthetic Simulations A (Complete Successful Incident) & H (Deterministic Replay)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from shared.artifacts import build_artifact_reference
from shared.config import load_dependency_graph, load_rollout_policy, load_route_registry
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    DeploymentStatus,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    IncidentState,
    OperationOutcome,
    PatchOrigin,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import (
    generate_approval_id,
    generate_artifact_id,
    generate_deployment_id,
    generate_finding_id,
    generate_incident_id,
    generate_operation_id,
    generate_patch_id,
    generate_rollout_decision_id,
    generate_rollout_plan_id,
    generate_rollout_stage_id,
    generate_test_run_id,
    generate_verification_id,
)
from shared.schemas import (
    ApprovalDecision,
    DeploymentEvidence,
    FeatureState,
    Finding,
    IncidentEvent,
    IndividualTestOutcome,
    LatencyStats,
    MetricSnapshot,
    OperationReceipt,
    PatchProposal,
    PatchTestResult,
    RolloutDecision,
    RolloutGuardrailConfig,
    RolloutPlan,
    RolloutStage,
    VerificationResult,
)
from shared.serialization import sha256_text

from agent_core.adapters.fixtures import (
    FixtureContainmentStrategistAdapter,
    FixtureFeatureMapperAdapter,
    FixtureInvestigatorAdapter,
)
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.idempotency import build_operation_idempotency_key
from agent_core.incident import IncidentAggregate
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository


@dataclass
class SimulationSummary:
    """Structured outcome summary emitted by local synthetic simulations."""

    name: str
    incident_id: str
    final_state: IncidentState
    incident_version: int
    event_count: int
    pending_requests_count: int
    replay_matched: bool
    is_synthetic: bool = True
    notes: str = ""


def _sim_producer(actor_type: ActorType, producer_id: str) -> ProducerContext:
    return ProducerContext(
        producer_id=producer_id,
        actor_type=actor_type,
        authenticated=True,
        trusted_channel="synthetic_simulation",
        provenance_mode="fixture",
    )


async def seed_artifact(
    repo: InMemoryOrchestrationRepository,
    *,
    incident_id: str,
    artifact_type: ArtifactType,
    content_text: str,
    revision: str = "rev_demo_001",
) -> str:
    """Helper storing an integrity-hashed synthetic artifact in the memory repo."""
    art_id = generate_artifact_id()
    ref = build_artifact_reference(
        artifact_id=art_id,
        incident_id=incident_id,
        artifact_type=artifact_type,
        content=content_text.encode("utf-8"),
        storage_ref=f"artifacts/sim/{incident_id}/{art_id}.json",
        producer="synthetic_simulation",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        source_revision=revision,
    )
    await repo.store_artifact(ref, content_text.encode("utf-8"))
    return art_id


async def run_successful_incident_simulation() -> tuple[
    SimulationSummary, list[IncidentEvent], IncidentAggregate
]:
    """Simulation A: End-to-end synthetic SQLi incident from intake to RECOVERED."""
    clock = FixedClock(datetime(2026, 11, 26, 2, 0, 0, tzinfo=UTC))
    repo = InMemoryOrchestrationRepository()
    registry = load_route_registry()
    dep_graph = load_dependency_graph()
    policy = load_rollout_policy()

    orchestrator = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=registry,
        clock=clock,
        fixture_mode=True,
        investigator=FixtureInvestigatorAdapter(),
        feature_mapper=FixtureFeatureMapperAdapter(),
        containment_strategist=FixtureContainmentStrategistAdapter(clock=clock),
    )

    incident_id = generate_incident_id()
    finding_id = generate_finding_id()
    rev = "rev_demo_001"

    finding = Finding(
        finding_id=finding_id,
        incident_id=incident_id,
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.CRITICAL,
        status=FindingStatus.SUSPECTED,
        evidence_ids=[],
        source_scanner="fixture_scanner",
        repository_revision=rev,
        environment=registry.environment,
        detected_at=clock.now(),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )

    # 1. Intake -> RECEIVED
    inc = await orchestrator.create_incident(
        finding, _sim_producer(ActorType.SECURITY_SCANNER, "sim_scanner")
    )
    corr_id = inc.correlation_id
    seq = 1

    async def step(
        event_type: EventType,
        actor_type: ActorType,
        actor: str,
        tctx: TransitionContext,
        *,
        causation_id: str | None = None,
        evidence_ids: list[str] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> IncidentEvent:
        nonlocal inc, seq
        clock.advance(10)
        seq += 1
        evt = build_incident_event(
            incident_id=incident_id,
            event_type=event_type,
            actor=actor,
            actor_type=actor_type,
            sequence_number=seq,
            correlation_id=corr_id,
            causation_id=causation_id,
            evidence_ids=evidence_ids or [],
            payload=payload or {},
            timestamp_utc=clock.now(),
        )
        res = await orchestrator.process_event(evt, tctx.producer_context, tctx)
        assert res.accepted, f"Simulation step {event_type.value} failed: {res.guard_failures}"
        latest = await orchestrator.get_incident(incident_id)
        assert latest is not None
        inc = latest
        return res.generated_events[0]

    # 2. Request verification -> VALIDATION_REQUESTED
    p_eng = _sim_producer(ActorType.DETERMINISTIC_ENGINE, "orchestrator_engine")
    evt_req = await step(
        EventType.VERIFICATION_REQUESTED,
        ActorType.DETERMINISTIC_ENGINE,
        "orchestrator_engine",
        TransitionContext(producer_context=p_eng, clock=clock, fixture_mode=True, finding=finding),
    )

    # 3-4. Reproduction confirmed -> REPRODUCED
    repro_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_text="repro=true",
        revision=rev,
    )
    repro_vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=incident_id,
        test_id="sqli_search_repro",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        observed_feature_state=True,
        expected_revision=rev,
        tested_revision=rev,
        artifact_ids=[repro_art],
        started_at=clock.now(),
        completed_at=clock.now() + timedelta(seconds=2),
        exit_code=0,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    p_ver = _sim_producer(ActorType.SECURITY_VERIFIER, "sim_verifier")
    await step(
        EventType.REPRODUCTION_CONFIRMED,
        ActorType.SECURITY_VERIFIER,
        "sim_verifier",
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            finding=finding,
            verification_result=repro_vr,
        ),
        causation_id=evt_req.event_id,
        evidence_ids=[repro_art],
    )

    # 5. Investigation (non-transition) + Mapping -> FLAG_MAPPED
    inv_summary = await orchestrator.run_investigation(finding, [])
    await step(
        EventType.INVESTIGATION_COMPLETED,
        ActorType.DETERMINISTIC_ENGINE,
        "fixture_investigator",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            finding=finding,
            investigation_summary=inv_summary,
        ),
    )
    search_v1_on = FeatureState(
        environment=registry.environment,
        feature_id="fs_search_v1",
        feature_name="search_v1",
        observation_status=FeatureObservationStatus.OBSERVED,
        enabled=True,
        observed_at=clock.now(),
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
        evidence_ids=[repro_art],
    )
    mapping = await orchestrator.run_mapping(finding, [search_v1_on])
    await step(
        EventType.MAPPING_MATCHED,
        ActorType.DETERMINISTIC_ENGINE,
        "fixture_mapper",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            finding=finding,
            mapping_result=mapping,
        ),
        evidence_ids=[repro_art],
    )

    # 7-8. Containment proposal -> CONTAINMENT_PROPOSED -> AWAITING_APPROVAL
    repro_finding = finding.model_copy(
        update={"status": FindingStatus.REPRODUCED, "evidence_ids": [repro_art]}
    )
    proposal = await orchestrator.run_containment_strategy(
        repro_finding, mapping, dep_graph, [search_v1_on]
    )
    evt_prop = await step(
        EventType.CONTAINMENT_PROPOSED,
        ActorType.DETERMINISTIC_ENGINE,
        "fixture_strategist",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            containment_proposal=proposal,
        ),
        evidence_ids=[repro_art],
        payload={
            "proposal_id": proposal.proposal_id,
            "proposal_hash": proposal.proposal_hash,
            "environment": proposal.environment,
            "flag_name": proposal.flag_name,
            "desired_enabled": proposal.desired_enabled,
        },
    )
    evt_await = await step(
        EventType.APPROVAL_REQUESTED,
        ActorType.DETERMINISTIC_ENGINE,
        "orchestrator_engine",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            active_proposal=proposal,
        ),
        causation_id=evt_prop.event_id,
    )

    # 9-10. Human approval -> APPLYING (emits non-executable fixture request)
    p_human = _sim_producer(ActorType.HUMAN_OPERATOR, "secops_demo_lead")
    approval = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,
        proposal_hash=proposal.proposal_hash,
        incident_id=incident_id,
        actor_id="secops_demo_lead",
        decision=ApprovalStatus.APPROVED,
        decided_at=clock.now() + timedelta(seconds=5),
        expires_at=proposal.expires_at,
        authorization_context_ref="authctx_sim_001",
        nonce="nonce_sim_001",
    )
    search_v1_on_fresh = search_v1_on.model_copy(update={"observed_at": clock.now()})
    evt_approved = await step(
        EventType.APPROVAL_GRANTED,
        ActorType.HUMAN_OPERATOR,
        "secops_demo_lead",
        TransitionContext(
            producer_context=p_human,
            clock=clock,
            fixture_mode=True,
            active_proposal=proposal,
            approval_decision=approval,
            feature_state=search_v1_on_fresh,
        ),
        causation_id=evt_await.event_id,
        evidence_ids=[repro_art],
    )

    # 11-12. Fixture operation receipt & readback -> CONTAINMENT_TEST_PENDING
    p_exec = _sim_producer(ActorType.PLATFORM_EXECUTOR, "fixture_platform_executor")
    receipt_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.OPERATION_RECEIPT,
        content_text="search_v1=false",
        revision=rev,
    )
    op_id = generate_operation_id()
    receipt = OperationReceipt(
        operation_id=op_id,
        incident_id=incident_id,
        proposal_id=proposal.proposal_id,
        approval_id=approval.approval_id,
        environment=registry.environment,
        target_feature="search_v1",
        requested_state=False,
        observed_state=False,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key=build_operation_idempotency_key(
            incident_id=incident_id,
            proposal_id=proposal.proposal_id,
            approval_id=approval.approval_id,
            environment=registry.environment,
            target_feature="search_v1",
            desired_enabled=False,
        ),
        executed_at=clock.now() + timedelta(seconds=5),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        evidence_ids=[receipt_art],
    )
    evt_exec = await step(
        EventType.FLAG_UPDATE_SUCCESS,
        ActorType.PLATFORM_EXECUTOR,
        "fixture_platform_executor",
        TransitionContext(
            producer_context=p_exec,
            clock=clock,
            fixture_mode=True,
            operation_receipt=receipt,
        ),
        causation_id=evt_approved.event_id,
        evidence_ids=[receipt_art],
    )

    # 13-15. Readback + Post-containment security + smoke test -> CONTAINED
    search_v1_off = search_v1_on.model_copy(
        update={"enabled": False, "observed_at": clock.now() + timedelta(seconds=12)}
    )
    await step(
        EventType.FLAG_STATE_OBSERVED,
        ActorType.PLATFORM_EXECUTOR,
        "fixture_platform_executor",
        TransitionContext(
            producer_context=p_exec,
            clock=clock,
            fixture_mode=True,
            feature_state=search_v1_off,
        ),
        evidence_ids=[receipt_art],
    )
    await step(
        EventType.FUNCTIONAL_SMOKE_TEST_PASSED,
        ActorType.SECURITY_VERIFIER,
        "sim_verifier",
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            functional_smoke_passed=True,
        ),
    )
    reg_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.REGRESSION_LOG,
        content_text="sqli_blocked=true",
        revision=rev,
    )
    post_vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=incident_id,
        test_id="sqli_search_regression",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        observed_feature_state=False,
        expected_revision=rev,
        tested_revision=rev,
        artifact_ids=[reg_art],
        started_at=clock.now() + timedelta(seconds=10),
        completed_at=clock.now() + timedelta(seconds=15),
        exit_code=0,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await step(
        EventType.CONTAINMENT_CONFIRMED,
        ActorType.SECURITY_VERIFIER,
        "sim_verifier",
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            verification_result=post_vr,
            feature_state=search_v1_off.model_copy(
                update={"observed_at": clock.now() + timedelta(seconds=12)}
            ),
            functional_smoke_passed=True,
        ),
        causation_id=evt_exec.event_id,
        evidence_ids=[reg_art],
    )

    # 16-17. Candidate patch & isolated tests -> PATCH_PENDING -> PATCH_TESTED
    await step(
        EventType.PATCH_REQUESTED,
        ActorType.DETERMINISTIC_ENGINE,
        "orchestrator_engine",
        TransitionContext(producer_context=p_eng, clock=clock, fixture_mode=True),
    )
    diff_text = "--- a/app/search.py\n+++ b/app/search.py\n-bad\n+good\n"
    patch_hash = sha256_text(diff_text)
    patch_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.PATCH_DIFF,
        content_text=diff_text,
        revision=rev,
    )
    patch_id = generate_patch_id()
    patch_prop = PatchProposal(
        patch_id=patch_id,
        incident_id=incident_id,
        finding_id=finding_id,
        source_revision=rev,
        candidate_artifact_id=patch_art,
        candidate_content_hash=patch_hash,
        unified_diff=diff_text,
        allowed_files=["app/search.py"],
        touched_files=["app/search.py"],
        technical_rationale="Use parameterized SQL query.",
        required_tests=["test_sqli_blocked", "test_search_ok"],
        patch_origin=PatchOrigin.REFERENCE_FIXTURE,
        created_at=clock.now(),
    )
    await step(
        EventType.PATCH_PROPOSED,
        ActorType.DETERMINISTIC_ENGINE,
        "fixture_patch_agent",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            patch_proposal=patch_prop,
        ),
        evidence_ids=[patch_art],
    )
    patch_test_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.PATCH_TEST_LOG,
        content_text="all passed",
        revision=rev,
    )
    patch_test_res = PatchTestResult(
        test_run_id=generate_test_run_id(),
        patch_id=patch_id,
        incident_id=incident_id,
        expected_source_revision=rev,
        tested_source_revision=rev,
        tested_candidate_hash=patch_hash,
        individual_outcomes=[
            IndividualTestOutcome(
                test_name="test_sqli_blocked",
                category="security",
                status=TestExecutionStatus.TEST_PASSED,
            ),
            IndividualTestOutcome(
                test_name="test_search_ok",
                category="functional",
                status=TestExecutionStatus.TEST_PASSED,
            ),
        ],
        overall_status=TestExecutionStatus.TEST_PASSED,
        artifact_ids=[patch_test_art],
        started_at=clock.now(),
        completed_at=clock.now() + timedelta(seconds=3),
        exit_code=0,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await step(
        EventType.PATCH_TEST_PASSED,
        ActorType.SECURITY_VERIFIER,
        "sim_verifier",
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            patch_proposal=patch_prop,
            patch_test_result=patch_test_res,
        ),
        evidence_ids=[patch_test_art],
    )

    # 18-19. Deployment verified & rollout plan created -> ROLLOUT_PENDING
    patched_rev = "rev_demo_002_patched"
    dep_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.DEPLOYMENT_MANIFEST,
        content_text=patched_rev,
        revision=patched_rev,
    )
    dep = DeploymentEvidence(
        deployment_id=generate_deployment_id(),
        environment=registry.environment,
        implementation_id="search_service_v2",
        feature_name="search_v2",
        source_revision=patched_rev,
        implementation_hash=patch_hash,
        deployed_at=clock.now(),
        deployment_status=DeploymentStatus.OBSERVED,
        addressable=True,
        evidence_ids=[dep_art],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    guardrails = RolloutGuardrailConfig(
        max_error_rate=policy.guardrails.max_error_rate,
        max_error_rate_increase_pp=policy.guardrails.max_error_rate_increase_pp,
        max_p95_latency_increase_percent=policy.guardrails.max_p95_latency_increase_percent,
    )
    stages = [
        RolloutStage(
            stage_id=generate_rollout_stage_id(),
            exposure_percentage=pct,
            required_metrics=["error_rate", "p95_ms"],
            minimum_observation_window_seconds=policy.minimum_observation_window_seconds,
            minimum_request_count=policy.minimum_request_count,
            guardrails=guardrails,
            approval_required=True,
        )
        for pct in policy.stages_percent
    ]
    plan = RolloutPlan(
        plan_id=generate_rollout_plan_id(),
        incident_id=incident_id,
        target_feature="search_v2",
        environment=registry.environment,
        target_implementation_revision=patched_rev,
        stages=stages,
        current_stage_id=stages[0].stage_id,
        guardrails=guardrails,
        evidence_ids=[dep_art, patch_test_art],
        approval_required=True,
    )
    await step(
        EventType.ROLLOUT_PLAN_CREATED,
        ActorType.DETERMINISTIC_ENGINE,
        "orchestrator_engine",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            patch_proposal=patch_prop,
            patch_test_result=patch_test_res,
            deployment_evidence=dep,
            rollout_plan=plan,
        ),
        evidence_ids=[dep_art, patch_test_art],
    )

    # 20-22. Simulate staged approvals + observations for 5%, 25%, 50%, 100% -> RECOVERED
    tele_art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.TELEMETRY_SNAPSHOT,
        content_text="healthy",
        revision=patched_rev,
    )
    for idx, st in enumerate(stages):
        stage_appr = ApprovalDecision(
            approval_id=generate_approval_id(),
            proposal_id=st.stage_id,
            proposal_hash=sha256_text(st.stage_id),
            incident_id=incident_id,
            actor_id="secops_demo_lead",
            decision=ApprovalStatus.APPROVED,
            decided_at=clock.now() + timedelta(seconds=1),
            expires_at=clock.now() + timedelta(minutes=10),
            authorization_context_ref=f"authctx_stage_{idx}",
            nonce=f"nonce_stage_{idx}",
        )
        await step(
            EventType.ROLLOUT_STAGE_APPROVED,
            ActorType.HUMAN_OPERATOR,
            "secops_demo_lead",
            TransitionContext(
                producer_context=p_human,
                clock=clock,
                fixture_mode=True,
                stage_approval_decision=stage_appr,
            ),
        )
        snap = MetricSnapshot(
            snapshot_id=f"met_sim_{idx:04d}",
            incident_id=incident_id,
            environment=registry.environment,
            feature_id="search_v2",
            observation_window_seconds=45,
            observed_at=clock.now(),
            request_count=200,
            failed_request_count=1,
            error_rate=0.005,
            latency_ms=LatencyStats(p50_ms=15.0, p95_ms=38.0, p99_ms=60.0),
            baseline_error_rate=0.005,
            baseline_p95_latency_ms=36.0,
            security_regression_passed=True,
            observed_rollout_stage_percentage=st.exposure_percentage,
            provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
            evidence_ids=[tele_art],
        )
        await step(
            EventType.ROLLOUT_METRICS_RECEIVED,
            ActorType.SYSTEM,
            "synthetic_telemetry",
            TransitionContext(
                producer_context=_sim_producer(ActorType.SYSTEM, "synthetic_telemetry"),
                clock=clock,
                fixture_mode=True,
                metric_snapshot=snap,
            ),
            evidence_ids=[tele_art],
        )
        if idx + 1 < len(stages):
            next_st = stages[idx + 1]
            dec = RolloutDecision(
                decision_id=generate_rollout_decision_id(),
                plan_id=plan.plan_id,
                incident_id=incident_id,
                current_stage_id=st.stage_id,
                proposed_next_stage_id=next_st.stage_id,
                decision_type=RolloutDecisionType.ADVANCE,
                evaluated_guardrails=["max_error_rate", "security_regression_passed"],
                passed_guardrails=["max_error_rate", "security_regression_passed"],
                explanation="Stage healthy.",
                evidence_ids=[tele_art],
                approval_required=True,
            )
            await step(
                EventType.ROLLOUT_ADVANCE_PROPOSED,
                ActorType.DETERMINISTIC_ENGINE,
                "fixture_release_manager",
                TransitionContext(
                    producer_context=p_eng,
                    clock=clock,
                    fixture_mode=True,
                    rollout_decision=dec,
                    metric_snapshot=snap,
                ),
            )
        else:
            fs_100 = FeatureState(
                environment=registry.environment,
                feature_id="fs_search_v2",
                feature_name="search_v1",
                observation_status=FeatureObservationStatus.OBSERVED,
                enabled=False,
                observed_at=clock.now(),
                observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
                segment_targeting={"exposure_percentage": 100, "target_feature": "search_v2"},
                evidence_ids=[tele_art],
            )
            await step(
                EventType.ROLLOUT_STAGE_OBSERVED,
                ActorType.PLATFORM_EXECUTOR,
                "fixture_platform_executor",
                TransitionContext(
                    producer_context=p_exec,
                    clock=clock,
                    fixture_mode=True,
                    feature_state=fs_100,
                    metric_snapshot=snap,
                ),
                evidence_ids=[tele_art],
                payload={"stage_id": st.stage_id, "observed_exposure": 100},
            )

    final_vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=incident_id,
        test_id="sqli_search_post_patch",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        observed_feature_state=True,
        expected_revision=patched_rev,
        tested_revision=patched_rev,
        artifact_ids=[tele_art],
        started_at=clock.now(),
        completed_at=clock.now() + timedelta(seconds=2),
        exit_code=0,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await step(
        EventType.ROLLOUT_COMPLETED,
        ActorType.DETERMINISTIC_ENGINE,
        "orchestrator_engine",
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            deployment_evidence=dep,
            verification_result=final_vr,
            metric_snapshot=snap,
        ),
        evidence_ids=[tele_art, dep_art],
    )

    # 23. Replay parity verification
    events = await orchestrator.get_incident_events(incident_id)
    replayed = await orchestrator.replay_incident(incident_id)
    parity = (
        replayed.current_state == inc.current_state
        and replayed.incident_version == inc.incident_version
        and replayed.current_proposal_id == inc.current_proposal_id
        and replayed.consumed_approval_ids == inc.consumed_approval_ids
        and replayed.rollout_stages == inc.rollout_stages
    )
    assert parity, "Replayed incident state diverged from live aggregate."

    pending = await repo.list_pending_requests(incident_id)
    assert all(not r.executable_live and r.is_synthetic_fixture for r in pending)

    return (
        SimulationSummary(
            name="Simulation A: Complete Successful Incident",
            incident_id=incident_id,
            final_state=inc.current_state,
            incident_version=inc.incident_version,
            event_count=len(events),
            pending_requests_count=len(pending),
            replay_matched=parity,
            notes="Full lifecycle from RECEIVED -> RECOVERED with 5/25/50/100% stages.",
        ),
        events,
        inc,
    )


async def run_replay_parity_simulation() -> SimulationSummary:
    """Simulation H: Record an incident and verify side-effect-free replay parity."""
    summary, events, live_agg = await run_successful_incident_simulation()
    replayed = await (lambda: _pure_replay_check(events, live_agg))()
    return SimulationSummary(
        name="Simulation H: Deterministic Incident Replay",
        incident_id=summary.incident_id,
        final_state=replayed.current_state,
        incident_version=replayed.incident_version,
        event_count=len(events),
        pending_requests_count=0,
        replay_matched=(replayed.current_state == live_agg.current_state),
        notes="Replay issued 0 external requests and matched stored aggregate state.",
    )


async def _pure_replay_check(
    events: list[IncidentEvent], live_agg: IncidentAggregate
) -> IncidentAggregate:
    from agent_core.replay import replay_incident

    replayed = replay_incident(events)
    assert replayed.current_state == live_agg.current_state
    assert replayed.incident_version == live_agg.incident_version
    assert replayed.latest_event_id == live_agg.latest_event_id
    return replayed
