"""Synthetic Simulations B (Rejected Containment) & C (Invalid/Expired Approval)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shared.config import load_dependency_graph, load_route_registry
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    IncidentState,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import (
    generate_approval_id,
    generate_finding_id,
    generate_incident_id,
    generate_test_run_id,
    generate_verification_id,
)
from shared.schemas import ApprovalDecision, FeatureState, Finding, VerificationResult

from agent_core.adapters.fixtures import (
    FixtureContainmentStrategistAdapter,
    FixtureFeatureMapperAdapter,
)
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.simulations.successful_incident import SimulationSummary, seed_artifact


async def _setup_awaiting_approval() -> tuple[
    IncidentOrchestrator,
    InMemoryOrchestrationRepository,
    FixedClock,
    str,
    str,
    str,
    FeatureState,
    object,
]:
    clock = FixedClock(datetime(2026, 11, 26, 3, 0, 0, tzinfo=UTC))
    repo = InMemoryOrchestrationRepository()
    registry = load_route_registry()
    dep_graph = load_dependency_graph()
    orchestrator = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=registry,
        clock=clock,
        fixture_mode=True,
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
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.SUSPECTED,
        repository_revision=rev,
        environment=registry.environment,
        detected_at=clock.now(),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    p_scan = ProducerContext(
        producer_id="sim_scanner",
        actor_type=ActorType.SECURITY_SCANNER,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    inc = await orchestrator.create_incident(finding, p_scan)
    corr_id = inc.correlation_id

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
    art = await seed_artifact(
        repo,
        incident_id=incident_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_text="repro",
        revision=rev,
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=incident_id,
            event_type=EventType.VERIFICATION_REQUESTED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=2,
            correlation_id=corr_id,
            timestamp_utc=clock.now(),
        ),
        p_eng,
        TransitionContext(producer_context=p_eng, clock=clock, fixture_mode=True, finding=finding),
    )
    vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=incident_id,
        test_id="sqli",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        expected_revision=rev,
        tested_revision=rev,
        artifact_ids=[art],
        started_at=clock.now(),
        completed_at=clock.now() + timedelta(seconds=1),
        exit_code=0,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=incident_id,
            event_type=EventType.REPRODUCTION_CONFIRMED,
            actor="sim_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id=corr_id,
            evidence_ids=[art],
            timestamp_utc=clock.now(),
        ),
        p_ver,
        TransitionContext(
            producer_context=p_ver,
            clock=clock,
            fixture_mode=True,
            finding=finding,
            verification_result=vr,
        ),
    )
    fs = FeatureState(
        environment=registry.environment,
        feature_id="fs_search_v1",
        feature_name="search_v1",
        observation_status=FeatureObservationStatus.OBSERVED,
        enabled=True,
        observed_at=clock.now(),
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
        evidence_ids=[art],
    )
    mapping = await orchestrator.run_mapping(finding, [fs])
    await orchestrator.process_event(
        build_incident_event(
            incident_id=incident_id,
            event_type=EventType.MAPPING_MATCHED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=4,
            correlation_id=corr_id,
            evidence_ids=[art],
            timestamp_utc=clock.now(),
        ),
        p_eng,
        TransitionContext(
            producer_context=p_eng,
            clock=clock,
            fixture_mode=True,
            finding=finding,
            mapping_result=mapping,
        ),
    )
    repro_f = finding.model_copy(update={"status": FindingStatus.REPRODUCED, "evidence_ids": [art]})
    proposal = await orchestrator.run_containment_strategy(repro_f, mapping, dep_graph, [fs])
    evt_prop = build_incident_event(
        incident_id=incident_id,
        event_type=EventType.CONTAINMENT_PROPOSED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=5,
        correlation_id=corr_id,
        evidence_ids=[art],
        timestamp_utc=clock.now(),
        payload={
            "proposal_id": proposal.proposal_id,
            "proposal_hash": proposal.proposal_hash,
            "environment": proposal.environment,
            "flag_name": proposal.flag_name,
            "desired_enabled": proposal.desired_enabled,
        },
    )
    await orchestrator.process_event(
        evt_prop,
        p_eng,
        TransitionContext(
            producer_context=p_eng, clock=clock, fixture_mode=True, containment_proposal=proposal
        ),
    )
    evt_await = build_incident_event(
        incident_id=incident_id,
        event_type=EventType.APPROVAL_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=6,
        correlation_id=corr_id,
        timestamp_utc=clock.now(),
    )
    await orchestrator.process_event(
        evt_await,
        p_eng,
        TransitionContext(
            producer_context=p_eng, clock=clock, fixture_mode=True, active_proposal=proposal
        ),
    )
    return orchestrator, repo, clock, incident_id, corr_id, evt_await.event_id, fs, proposal


async def run_rejected_containment_simulation() -> SimulationSummary:
    """Simulation B: Human rejects containment proposal -> REJECTED, 0 execution requests."""
    (
        orchestrator,
        repo,
        clock,
        inc_id,
        corr_id,
        await_evt_id,
        _fs,
        proposal,
    ) = await _setup_awaiting_approval()
    p_human = ProducerContext(
        producer_id="secops_lead",
        actor_type=ActorType.HUMAN_OPERATOR,
        authenticated=True,
        trusted_channel="sim_ui",
        provenance_mode="fixture",
    )
    rejected = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        proposal_hash=proposal.proposal_hash,  # type: ignore[attr-defined]
        incident_id=inc_id,
        actor_id="secops_lead",
        decision=ApprovalStatus.REJECTED,
        decided_at=clock.now() + timedelta(seconds=5),
        expires_at=proposal.expires_at,  # type: ignore[attr-defined]
        rejection_reason="Operator rejected automated disablement during peak traffic.",
        authorization_context_ref="authctx_rej_001",
        nonce="nonce_rej_001",
    )
    res = await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.APPROVAL_REJECTED,
            actor="secops_lead",
            actor_type=ActorType.HUMAN_OPERATOR,
            sequence_number=7,
            correlation_id=corr_id,
            causation_id=await_evt_id,
            timestamp_utc=clock.now() + timedelta(seconds=5),
        ),
        p_human,
        TransitionContext(
            producer_context=p_human,
            clock=clock,
            fixture_mode=True,
            active_proposal=proposal,  # type: ignore[arg-type]
            approval_decision=rejected,
        ),
    )
    assert res.accepted and res.current_state == IncidentState.REJECTED
    pending = await repo.list_pending_requests(inc_id)
    flag_exec_reqs = [r for r in pending if r.request_type == "platform_flag_execution_request"]
    assert len(flag_exec_reqs) == 0
    replayed = await orchestrator.replay_incident(inc_id)
    events = await orchestrator.get_incident_events(inc_id)
    return SimulationSummary(
        name="Simulation B: Rejected Containment",
        incident_id=inc_id,
        final_state=res.current_state,
        incident_version=res.incident_version,
        event_count=len(events),
        pending_requests_count=len(flag_exec_reqs),
        replay_matched=(replayed.current_state == IncidentState.REJECTED),
        notes="Human rejection halted execution with 0 flag execution requests.",
    )


async def run_invalid_or_expired_approval_simulation() -> SimulationSummary:
    """Simulation C: Expired and mismatched-hash approvals cannot enter APPLYING."""
    (
        orchestrator,
        _repo,
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
    bad_hash_appr = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        proposal_hash="f" * 64,
        incident_id=inc_id,
        actor_id="secops_lead",
        decision=ApprovalStatus.APPROVED,
        decided_at=clock.now(),
        expires_at=proposal.expires_at,  # type: ignore[attr-defined]
        authorization_context_ref="authctx_bad_001",
        nonce="nonce_bad_001",
    )
    res_bad = await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.APPROVAL_GRANTED,
            actor="secops_lead",
            actor_type=ActorType.HUMAN_OPERATOR,
            sequence_number=7,
            correlation_id=corr_id,
            causation_id=await_evt_id,
            timestamp_utc=clock.now(),
        ),
        p_human,
        TransitionContext(
            producer_context=p_human,
            clock=clock,
            fixture_mode=True,
            active_proposal=proposal,  # type: ignore[arg-type]
            approval_decision=bad_hash_appr,
            feature_state=fs,
        ),
    )
    assert not res_bad.accepted and res_bad.current_state == IncidentState.AWAITING_APPROVAL

    # Advance clock past expiration and test expired approval
    valid_appr = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        proposal_hash=proposal.proposal_hash,  # type: ignore[attr-defined]
        incident_id=inc_id,
        actor_id="secops_lead",
        decision=ApprovalStatus.APPROVED,
        decided_at=clock.now(),
        expires_at=clock.now() + timedelta(minutes=5),
        authorization_context_ref="authctx_exp_001",
        nonce="nonce_exp_001",
    )
    clock.advance(600)
    res_exp = await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.APPROVAL_GRANTED,
            actor="secops_lead",
            actor_type=ActorType.HUMAN_OPERATOR,
            sequence_number=7,
            correlation_id=corr_id,
            causation_id=await_evt_id,
            timestamp_utc=clock.now(),
        ),
        p_human,
        TransitionContext(
            producer_context=p_human,
            clock=clock,
            fixture_mode=True,
            active_proposal=proposal,  # type: ignore[arg-type]
            approval_decision=valid_appr,
            feature_state=fs,
        ),
    )
    assert not res_exp.accepted and res_exp.current_state == IncidentState.AWAITING_APPROVAL
    events = await orchestrator.get_incident_events(inc_id)
    replayed = await orchestrator.replay_incident(inc_id)
    return SimulationSummary(
        name="Simulation C: Invalid & Expired Approvals Denied",
        incident_id=inc_id,
        final_state=IncidentState.AWAITING_APPROVAL,
        incident_version=res_exp.incident_version,
        event_count=len(events),
        pending_requests_count=0,
        replay_matched=(replayed.current_state == IncidentState.AWAITING_APPROVAL),
        notes="Both mismatched proposal_hash and expired approval remained in AWAITING_APPROVAL.",
    )
