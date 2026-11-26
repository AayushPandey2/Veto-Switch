"""Category E: Idempotency tests for duplicate delivery, conflicts, and operation keys."""

from __future__ import annotations

import pytest
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.idempotency import build_operation_idempotency_key
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.tests.conftest import make_finding, make_producer
from shared.enums import ActorType, EventType, IncidentState
from shared.exceptions import IdempotencyConflictError


@pytest.mark.unit
def test_operation_idempotency_key_stability_and_sensitivity() -> None:
    k1 = build_operation_idempotency_key(
        incident_id="inc_01",
        proposal_id="prop_01",
        approval_id="appr_01",
        environment="demo-staging",
        target_feature="search_v1",
        desired_enabled=False,
    )
    k2 = build_operation_idempotency_key(
        incident_id="inc_01",
        proposal_id="prop_01",
        approval_id="appr_01",
        environment="demo-staging",
        target_feature="search_v1",
        desired_enabled=False,
    )
    k_changed_prop = build_operation_idempotency_key(
        incident_id="inc_01",
        proposal_id="prop_02",
        approval_id="appr_01",
        environment="demo-staging",
        target_feature="search_v1",
        desired_enabled=False,
    )
    k_stage = build_operation_idempotency_key(
        incident_id="inc_01",
        proposal_id="prop_01",
        approval_id="appr_01",
        environment="demo-staging",
        target_feature="search_v1",
        desired_enabled=True,
        operation_kind="rollout_stage_update",
        stage_id="rstage_25",
    )
    assert k1 == k2
    assert k1 != k_changed_prop
    assert k1 != k_stage


@pytest.mark.integration
async def test_duplicate_event_and_conflicting_duplicate_content(
    live_orchestrator: IncidentOrchestrator, fixed_clock: FixedClock
) -> None:
    finding = make_finding(incident_id="inc_idem_001")
    inc = await live_orchestrator.create_incident(
        finding, make_producer(ActorType.SECURITY_SCANNER)
    )
    p_eng = make_producer(ActorType.DETERMINISTIC_ENGINE)
    evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
        payload={"note": "first"},
    )
    ctx = TransitionContext(producer_context=p_eng, clock=fixed_clock, finding=finding)

    first = await live_orchestrator.process_event(evt, p_eng, ctx)
    assert first.accepted and not first.duplicate
    assert first.incident_version == 2
    assert len(first.pending_requests) == 1

    dup = await live_orchestrator.process_event(evt, p_eng, ctx)
    assert dup.accepted and dup.duplicate
    assert dup.incident_version == 2
    assert dup.pending_requests == []
    assert dup.reason_code == "DUPLICATE_EVENT_IGNORED"

    # Same event_id with altered payload raises IdempotencyConflictError
    conflicting = evt.model_copy(update={"payload": {"note": "tampered"}})
    with pytest.raises(IdempotencyConflictError):
        await live_orchestrator.process_event(conflicting, p_eng, ctx)

    events = await live_orchestrator.get_incident_events(inc.incident_id)
    assert len(events) == 2
    stored = await live_orchestrator.get_incident(inc.incident_id)
    assert stored is not None
    assert stored.current_state == IncidentState.VALIDATION_REQUESTED
    assert stored.incident_version == 2
