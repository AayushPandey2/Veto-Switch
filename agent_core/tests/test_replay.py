"""Category G: Deterministic incident replay and malformed-history rejection tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from agent_core.events import build_incident_event
from agent_core.replay import replay_incident, verify_event_history_integrity
from agent_core.simulations.containment_failure import run_containment_failure_simulation
from agent_core.simulations.recovery_failure import (
    run_patch_failure_simulation,
    run_rollout_failure_simulation,
)
from agent_core.simulations.rejected_incident import run_rejected_containment_simulation
from agent_core.simulations.successful_incident import run_successful_incident_simulation
from shared.enums import ActorType, EventType, IncidentState
from shared.exceptions import ReplayIntegrityError


@pytest.mark.integration
async def test_replay_matches_live_state_across_all_scenarios() -> None:
    summary_a, events_a, live_a = await run_successful_incident_simulation()
    replayed_a = replay_incident(events_a)
    assert replayed_a.current_state == IncidentState.RECOVERED
    assert replayed_a.incident_version == live_a.incident_version
    assert replayed_a.consumed_approval_ids == live_a.consumed_approval_ids
    assert replayed_a.rollout_stages == live_a.rollout_stages

    # Historical replay remains deterministic regardless of current wall clock
    # (never re-evaluates expiration)
    replayed_again = replay_incident(events_a)
    assert replayed_again == replayed_a

    sim_b = await run_rejected_containment_simulation()
    sim_d = await run_containment_failure_simulation()
    sim_e = await run_patch_failure_simulation()
    sim_f = await run_rollout_failure_simulation()
    assert all(s.replay_matched for s in (summary_a, sim_b, sim_d, sim_e, sim_f))


@pytest.mark.unit
def test_replay_rejects_empty_duplicate_out_of_order_and_mixed_histories() -> None:
    with pytest.raises(ReplayIntegrityError):
        verify_event_history_integrity([])

    t0 = datetime(2026, 11, 26, 4, 0, 0, tzinfo=UTC)
    e1 = build_incident_event(
        incident_id="inc_rep_1",
        event_type=EventType.FINDING_RECEIVED,
        actor="scanner",
        actor_type=ActorType.SECURITY_SCANNER,
        sequence_number=1,
        timestamp_utc=t0,
        payload={
            "finding_id": "fnd_1",
            "category": "sql_injection",
            "severity": "high",
            "status": "suspected",
            "environment": "demo-staging",
        },
    )
    e2_gap = build_incident_event(
        incident_id="inc_rep_1",
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=3,
        correlation_id=e1.correlation_id,
        timestamp_utc=t0,
    )
    with pytest.raises(ReplayIntegrityError):
        replay_incident([e1, e2_gap])

    e2_dup_id = e2_gap.model_copy(update={"event_id": e1.event_id, "sequence_number": 2})
    with pytest.raises(ReplayIntegrityError):
        replay_incident([e1, e2_dup_id])

    e2_mixed_inc = e2_gap.model_copy(update={"incident_id": "inc_other", "sequence_number": 2})
    with pytest.raises(ReplayIntegrityError):
        replay_incident([e1, e2_mixed_inc])
