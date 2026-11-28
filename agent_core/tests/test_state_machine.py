"""Category A: Deterministic state-machine structural and transition tests."""

from __future__ import annotations

import pytest
from agent_core.state_machine import (
    can_transition,
    get_allowed_events,
    get_target_state,
    is_non_transition_event,
)
from agent_core.transitions import TRANSITION_RULES
from shared.enums import EventType, IncidentState
from shared.exceptions import InvalidTransitionError


@pytest.mark.unit
@pytest.mark.parametrize(
    ("from_state", "event_type", "expected_to_state"),
    [(r.from_state, r.event_type, r.to_state) for r in TRANSITION_RULES],
)
def test_every_registered_transition_is_deterministic(
    from_state: IncidentState,
    event_type: EventType,
    expected_to_state: IncidentState,
) -> None:
    assert can_transition(from_state, event_type) is True
    assert get_target_state(from_state, event_type) == expected_to_state
    assert event_type in get_allowed_events(from_state)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("from_state", "forbidden_event"),
    [
        # Skipping intermediate states
        (IncidentState.RECEIVED, EventType.APPROVAL_GRANTED),
        (IncidentState.RECEIVED, EventType.CONTAINMENT_CONFIRMED),
        (IncidentState.RECEIVED, EventType.ROLLOUT_COMPLETED),
        (IncidentState.VALIDATION_REQUESTED, EventType.CONTAINMENT_PROPOSED),
        (IncidentState.FLAG_MAPPED, EventType.FLAG_UPDATE_SUCCESS),
        (IncidentState.CONTAINMENT_PROPOSED, EventType.APPROVAL_GRANTED),
        (IncidentState.AWAITING_APPROVAL, EventType.FLAG_UPDATE_SUCCESS),
        (IncidentState.AWAITING_APPROVAL, EventType.CONTAINMENT_CONFIRMED),
        (IncidentState.CONTAINED, EventType.ROLLOUT_PLAN_CREATED),
        (IncidentState.PATCH_PENDING, EventType.ROLLOUT_COMPLETED),
        # Forbidden arbitrary exits from failure/terminal states
        (IncidentState.REJECTED, EventType.APPROVAL_GRANTED),
        (IncidentState.UNMAPPED, EventType.CONTAINMENT_PROPOSED),
        (IncidentState.PATCH_FAILED, EventType.ROLLOUT_PLAN_CREATED),
        (IncidentState.RECOVERED, EventType.APPROVAL_GRANTED),
    ],
)
def test_forbidden_and_state_skipping_transitions_fail(
    from_state: IncidentState,
    forbidden_event: EventType,
) -> None:
    assert can_transition(from_state, forbidden_event) is False
    with pytest.raises(InvalidTransitionError):
        get_target_state(from_state, forbidden_event)


@pytest.mark.unit
def test_non_transition_events_preserve_top_level_state() -> None:
    assert is_non_transition_event(IncidentState.REPRODUCED, EventType.INVESTIGATION_COMPLETED)
    assert (
        get_target_state(IncidentState.REPRODUCED, EventType.INVESTIGATION_COMPLETED)
        == IncidentState.REPRODUCED
    )
    assert is_non_transition_event(
        IncidentState.ROLLOUT_PENDING, EventType.ROLLOUT_METRICS_RECEIVED
    )
    assert (
        get_target_state(IncidentState.ROLLOUT_PENDING, EventType.ROLLOUT_METRICS_RECEIVED)
        == IncidentState.ROLLOUT_PENDING
    )
