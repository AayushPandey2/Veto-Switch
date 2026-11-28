"""Tests for the immutable IncidentAggregate and controlled versioned updates."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from agent_core.tests.conftest import make_incident
from pydantic import ValidationError
from shared.enums import IncidentState


@pytest.mark.unit
def test_incident_aggregate_prevents_direct_state_mutation() -> None:
    inc = make_incident(state=IncidentState.RECEIVED)
    with pytest.raises(ValidationError):
        inc.current_state = IncidentState.CONTAINED  # type: ignore[misc]


@pytest.mark.unit
def test_incident_with_transition_increments_version_monotonically() -> None:
    inc = make_incident(state=IncidentState.RECEIVED)
    assert inc.incident_version == 1
    nxt = inc.with_transition(
        new_state=IncidentState.VALIDATION_REQUESTED,
        event_id="evt_next_0001",
        event_sequence=2,
        updated_at=datetime(2026, 11, 26, 4, 5, 0, tzinfo=UTC),
        updates={"pending_action": "await_verification_evidence"},
    )
    assert inc.current_state == IncidentState.RECEIVED
    assert inc.incident_version == 1
    assert nxt.current_state == IncidentState.VALIDATION_REQUESTED
    assert nxt.incident_version == 2
    assert nxt.latest_event_sequence == 2
    record = nxt.to_incident_record()
    assert record.state == IncidentState.VALIDATION_REQUESTED
    assert record.version == 2
