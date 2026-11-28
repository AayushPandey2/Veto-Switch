"""Synthetic Simulations D (Failed Containment) & G (Duplicate Events Idempotency)."""

from __future__ import annotations

from datetime import timedelta

from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    IncidentState,
    OperationOutcome,
)
from shared.identifiers import generate_approval_id, generate_operation_id
from shared.schemas import ApprovalDecision, OperationReceipt

from agent_core.context import ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.idempotency import build_operation_idempotency_key
from agent_core.simulations.rejected_incident import _setup_awaiting_approval
from agent_core.simulations.successful_incident import SimulationSummary, seed_artifact


async def run_containment_failure_simulation() -> SimulationSummary:
    """Simulation D: Flag change succeeded, post-change verification failed."""
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
    appr = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        proposal_hash=proposal.proposal_hash,  # type: ignore[attr-defined]
        incident_id=inc_id,
        actor_id="secops_lead",
        decision=ApprovalStatus.APPROVED,
        decided_at=clock.now(),
        expires_at=proposal.expires_at,  # type: ignore[attr-defined]
        authorization_context_ref="authctx_cf_001",
        nonce="nonce_cf_001",
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

    p_exec = ProducerContext(
        producer_id="fixture_executor",
        actor_type=ActorType.PLATFORM_EXECUTOR,
        authenticated=True,
        trusted_channel="sim_exec",
        provenance_mode="fixture",
    )
    rec_art = await seed_artifact(
        repo,
        incident_id=inc_id,
        artifact_type=ArtifactType.OPERATION_RECEIPT,
        content_text="search_v1=false",
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
        executed_at=clock.now() + timedelta(seconds=5),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        evidence_ids=[rec_art],
    )
    await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.FLAG_UPDATE_SUCCESS,
            actor="fixture_executor",
            actor_type=ActorType.PLATFORM_EXECUTOR,
            sequence_number=8,
            correlation_id=corr_id,
            causation_id=evt_appr.event_id,
            evidence_ids=[rec_art],
            timestamp_utc=clock.now() + timedelta(seconds=5),
        ),
        p_exec,
        TransitionContext(
            producer_context=p_exec, clock=clock, fixture_mode=True, operation_receipt=receipt
        ),
    )

    p_ver = ProducerContext(
        producer_id="sim_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="sim",
        provenance_mode="fixture",
    )
    res_fail = await orchestrator.process_event(
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.CONTAINMENT_VERIFICATION_FAILED,
            actor="sim_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=9,
            correlation_id=corr_id,
            timestamp_utc=clock.now() + timedelta(seconds=10),
            payload={"reason": "Alternate bypass route still reproduced SQLi."},
        ),
        p_ver,
        TransitionContext(producer_context=p_ver, clock=clock, fixture_mode=True),
    )
    assert res_fail.accepted and res_fail.current_state == IncidentState.CONTAINMENT_FAILED
    events = await orchestrator.get_incident_events(inc_id)
    replayed = await orchestrator.replay_incident(inc_id)
    return SimulationSummary(
        name="Simulation D: Failed Containment Verification",
        incident_id=inc_id,
        final_state=IncidentState.CONTAINMENT_FAILED,
        incident_version=res_fail.incident_version,
        event_count=len(events),
        pending_requests_count=len(await repo.list_pending_requests(inc_id)),
        replay_matched=(replayed.current_state == IncidentState.CONTAINMENT_FAILED),
        notes=(
            "Incident halted in CONTAINMENT_FAILED when regression test still reproduced exploit."
        ),
    )


async def run_duplicate_events_simulation() -> SimulationSummary:
    """Simulation G: Duplicate approval & receipt delivery preserves version & single operation."""
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
    appr = ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal.proposal_id,  # type: ignore[attr-defined]
        proposal_hash=proposal.proposal_hash,  # type: ignore[attr-defined]
        incident_id=inc_id,
        actor_id="secops_lead",
        decision=ApprovalStatus.APPROVED,
        decided_at=clock.now(),
        expires_at=proposal.expires_at,  # type: ignore[attr-defined]
        authorization_context_ref="authctx_dup_001",
        nonce="nonce_dup_001",
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
    ctx_appr = TransitionContext(
        producer_context=p_human,
        clock=clock,
        fixture_mode=True,
        active_proposal=proposal,  # type: ignore[arg-type]
        approval_decision=appr,
        feature_state=fs,
    )
    first = await orchestrator.process_event(evt_appr, p_human, ctx_appr)
    dup = await orchestrator.process_event(evt_appr, p_human, ctx_appr)
    assert first.accepted and not first.duplicate
    assert dup.accepted and dup.duplicate
    assert dup.incident_version == first.incident_version

    pending = await repo.list_pending_requests(inc_id)
    exec_reqs = [r for r in pending if r.request_type == "platform_flag_execution_request"]
    assert len(exec_reqs) == 1

    events = await orchestrator.get_incident_events(inc_id)
    replayed = await orchestrator.replay_incident(inc_id)
    return SimulationSummary(
        name="Simulation G: Duplicate Event Idempotency",
        incident_id=inc_id,
        final_state=IncidentState.APPLYING,
        incident_version=first.incident_version,
        event_count=len(events),
        pending_requests_count=len(exec_reqs),
        replay_matched=(replayed.incident_version == first.incident_version),
        notes=(
            "Duplicate APPROVAL_GRANTED delivery produced 0 extra versions "
            "and 1 logical operation."
        ),
    )
