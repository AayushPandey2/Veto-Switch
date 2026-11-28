"""Tests for transition registry completeness, recovery routes, and Mermaid export."""

from __future__ import annotations

import pytest
from agent_core.state_machine import can_transition, get_target_state
from agent_core.transitions import (
    EVIDENCE_REQUIREMENTS,
    TRANSITION_RULES,
    generate_mermaid_state_diagram,
)
from shared.enums import EventType, IncidentState


@pytest.mark.unit
def test_recovery_transitions_exist_with_explicit_triggers() -> None:
    assert get_target_state(IncidentState.UNVERIFIED, EventType.VERIFICATION_REQUESTED) == (
        IncidentState.VALIDATION_REQUESTED
    )
    assert get_target_state(IncidentState.UNMAPPED, EventType.MAPPING_MATCHED) == (
        IncidentState.FLAG_MAPPED
    )
    assert get_target_state(IncidentState.REJECTED, EventType.CONTAINMENT_PROPOSED) == (
        IncidentState.CONTAINMENT_PROPOSED
    )
    assert get_target_state(IncidentState.CHANGE_FAILED, EventType.FLAG_UPDATE_SUCCESS) == (
        IncidentState.CONTAINMENT_TEST_PENDING
    )
    assert get_target_state(IncidentState.PATCH_FAILED, EventType.PATCH_REQUESTED) == (
        IncidentState.PATCH_PENDING
    )
    assert get_target_state(IncidentState.ROLLOUT_PAUSED, EventType.ROLLBACK_PROPOSED) == (
        IncidentState.ROLLBACK_PROPOSED
    )
    # Verified rollback returns to CONTAINED, never directly to RECOVERED
    assert (
        get_target_state(IncidentState.ROLLBACK_PROPOSED, EventType.ROLLBACK_VERIFICATION_PASSED)
        == IncidentState.CONTAINED
    )
    assert can_transition(IncidentState.ROLLBACK_PROPOSED, EventType.ROLLOUT_COMPLETED) is False
    # Reopening recovered incident
    assert get_target_state(IncidentState.RECOVERED, EventType.INCIDENT_REOPENED) == (
        IncidentState.VALIDATION_REQUESTED
    )


@pytest.mark.unit
def test_evidence_requirements_cover_all_critical_states() -> None:
    critical_states = {
        IncidentState.REPRODUCED,
        IncidentState.FLAG_MAPPED,
        IncidentState.CONTAINMENT_PROPOSED,
        IncidentState.APPLYING,
        IncidentState.CONTAINMENT_TEST_PENDING,
        IncidentState.CONTAINED,
        IncidentState.PATCH_TESTED,
        IncidentState.ROLLOUT_PENDING,
        IncidentState.RECOVERED,
    }
    assert critical_states.issubset(set(EVIDENCE_REQUIREMENTS.keys()))
    for state in critical_states:
        assert len(EVIDENCE_REQUIREMENTS[state]) >= 4


@pytest.mark.unit
def test_generated_mermaid_diagram_contains_all_registered_edges() -> None:
    diagram = generate_mermaid_state_diagram()
    assert diagram.startswith("stateDiagram-v2")
    for rule in TRANSITION_RULES:
        expected = f"{rule.from_state.value} --> {rule.to_state.value} : {rule.event_type.value}"
        assert expected in diagram
