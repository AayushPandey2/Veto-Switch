"""Category D: Event schema, classification, ordering, causality, and pipeline tests."""

from __future__ import annotations

import pytest
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import (
    EventClassification,
    build_incident_event,
    classify_event,
    validate_event_ordering_and_causality,
)
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.tests.conftest import make_finding, make_producer
from shared.enums import ActorType, EventType, IncidentState
from shared.exceptions import ContractValidationError, InvalidTransitionError


@pytest.mark.unit
def test_event_classification_distinguishes_commands_notifications_and_decisions() -> None:
    assert classify_event(EventType.VERIFICATION_REQUESTED) == EventClassification.COMMAND
    assert classify_event(EventType.APPROVAL_GRANTED) == EventClassification.EXTERNAL_NOTIFICATION
    assert classify_event(EventType.CONTAINMENT_PROPOSED) == EventClassification.INTERNAL_DECISION


@pytest.mark.unit
async def test_event_ordering_causality_and_unknown_incident_rejection(
    live_orchestrator: IncidentOrchestrator, fixed_clock: FixedClock
) -> None:
    finding = make_finding(incident_id="inc_evt_001")
    inc = await live_orchestrator.create_incident(
        finding, make_producer(ActorType.SECURITY_SCANNER)
    )

    # Out-of-order sequence number (expected 2, sent 4)
    bad_seq = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=4,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    res_seq = await live_orchestrator.process_event(
        bad_seq,
        make_producer(ActorType.DETERMINISTIC_ENGINE),
    )
    assert not res_seq.accepted
    assert res_seq.reason_code == "INVALID_STATE_TRANSITION"

    # Mismatched correlation_id
    bad_corr = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id="corr_wrong_9999",
        timestamp_utc=fixed_clock.now(),
    )
    with pytest.raises(ContractValidationError):
        validate_event_ordering_and_causality(inc, bad_corr)

    # Missing causation_id on APPROVAL_GRANTED
    no_cause = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.APPROVAL_GRANTED,
        actor="secops",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        causation_id=None,
        timestamp_utc=fixed_clock.now(),
    )
    with pytest.raises(InvalidTransitionError):
        validate_event_ordering_and_causality(inc, no_cause)

    # Unknown incident returns structured rejection
    unknown_evt = build_incident_event(
        incident_id="inc_does_not_exist",
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    res_unknown = await live_orchestrator.process_event(
        unknown_evt,
        make_producer(ActorType.DETERMINISTIC_ENGINE),
        TransitionContext(
            producer_context=make_producer(ActorType.DETERMINISTIC_ENGINE),
            clock=fixed_clock,
        ),
    )
    assert not res_unknown.accepted
    assert res_unknown.reason_code == "INCIDENT_NOT_FOUND"
    # Verify original incident remains untouched at RECEIVED
    current = await live_orchestrator.get_incident(inc.incident_id)
    assert current is not None and current.current_state == IncidentState.RECEIVED
