"""Category F: Optimistic concurrency control & race condition tests."""

from __future__ import annotations

import asyncio

import pytest
from agent_core.context import EventProcessingResult, FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.simulations.rejected_incident import _setup_awaiting_approval
from agent_core.tests.conftest import make_approval, make_finding, make_producer
from shared.enums import ActorType, ApprovalStatus, EventType, IncidentState
from shared.exceptions import ConcurrencyConflictError


@pytest.mark.integration
async def test_repository_rejects_stale_incident_version_commit(
    memory_repo: InMemoryOrchestrationRepository,
    live_orchestrator: IncidentOrchestrator,
    fixed_clock: FixedClock,
) -> None:
    finding = make_finding(incident_id="inc_conc_001")
    inc = await live_orchestrator.create_incident(
        finding, make_producer(ActorType.SECURITY_SCANNER)
    )
    p_eng = make_producer(ActorType.DETERMINISTIC_ENGINE)
    evt2 = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    res = await live_orchestrator.process_event(
        evt2,
        p_eng,
        TransitionContext(producer_context=p_eng, clock=fixed_clock, finding=finding),
    )
    assert res.accepted and res.incident_version == 2

    # Attempting to commit with stale expected_version=1 must fail
    evt_stale = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=3,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    stale_updated = inc.with_transition(
        new_state=IncidentState.VALIDATION_REQUESTED,
        event_id=evt_stale.event_id,
        event_sequence=3,
        updated_at=fixed_clock.now(),
    )
    with pytest.raises(ConcurrencyConflictError):
        await memory_repo.commit_transition(
            expected_version=1,
            updated_incident=stale_updated,
            event=evt_stale,
            result=EventProcessingResult(
                accepted=True,
                incident_id=inc.incident_id,
                event_id=evt_stale.event_id,
                previous_state=IncidentState.RECEIVED,
                current_state=IncidentState.VALIDATION_REQUESTED,
                incident_version=2,
                reason_code="TEST",
            ),
        )


@pytest.mark.integration
async def test_concurrent_approval_and_rejection_allows_only_one_winner() -> None:
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
    p_human = make_producer(ActorType.HUMAN_OPERATOR, provenance_mode="fixture")

    appr_yes = make_approval(
        proposal,  # type: ignore[arg-type]
        decided_at=clock.now(),
        decision=ApprovalStatus.APPROVED,
    )
    appr_no = make_approval(
        proposal,  # type: ignore[arg-type]
        decided_at=clock.now(),
        decision=ApprovalStatus.REJECTED,
        rejection_reason="Concurrent rejection",
    )

    evt_yes = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.APPROVAL_GRANTED,
        actor="op_a",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=7,
        correlation_id=corr_id,
        causation_id=await_evt_id,
        evidence_ids=list(proposal.evidence_ids),  # type: ignore[attr-defined]
        timestamp_utc=clock.now(),
    )
    evt_no = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.APPROVAL_REJECTED,
        actor="op_b",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=7,
        correlation_id=corr_id,
        causation_id=await_evt_id,
        timestamp_utc=clock.now(),
    )

    res_yes, res_no = await asyncio.gather(
        orchestrator.process_event(
            evt_yes,
            p_human,
            TransitionContext(
                producer_context=p_human,
                clock=clock,
                fixture_mode=True,
                active_proposal=proposal,  # type: ignore[arg-type]
                approval_decision=appr_yes,
                feature_state=fs,
            ),
        ),
        orchestrator.process_event(
            evt_no,
            p_human,
            TransitionContext(
                producer_context=p_human,
                clock=clock,
                fixture_mode=True,
                active_proposal=proposal,  # type: ignore[arg-type]
                approval_decision=appr_no,
            ),
        ),
    )

    accepted_count = int(res_yes.accepted) + int(res_no.accepted)
    assert accepted_count == 1
    loser = res_no if res_yes.accepted else res_yes
    assert loser.accepted is False
    assert loser.reason_code in ("CONCURRENCY_CONFLICT", "INVALID_STATE_TRANSITION")
    final_inc = await orchestrator.get_incident(inc_id)
    assert final_inc is not None
    assert final_inc.current_state in (IncidentState.APPLYING, IncidentState.REJECTED)
