"""Category C: Human approval identity, freshness, consumption, and anti-spoofing tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.state_machine import validate_transition
from agent_core.tests.conftest import (
    make_approval,
    make_feature_state,
    make_incident,
    make_producer,
    make_proposal,
)
from shared.enums import ActorType, ApprovalStatus, EventType, IncidentState
from shared.identifiers import generate_proposal_id
from shared.schemas import RouteFlagRegistry


@pytest.mark.unit
@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("missing_approval", "MISSING_APPROVAL_DECISION"),
        ("rejected_decision", "INVALID_APPROVAL_BINDING"),
        ("expired_approval", "APPROVAL_EXPIRED"),
        ("wrong_proposal_id", "INVALID_APPROVAL_BINDING"),
        ("wrong_proposal_hash", "INVALID_APPROVAL_BINDING"),
        ("wrong_environment", "UNAUTHORIZED_ENVIRONMENT"),
        ("unknown_feature", "UNKNOWN_FEATURE_FLAG"),
        ("superseded_proposal", "SUPERSEDED_PROPOSAL"),
        ("consumed_approval", "APPROVAL_ALREADY_CONSUMED"),
        ("feature_state_drifted", "FEATURE_STATE_DRIFT"),
        ("ai_self_approval", "ACTOR_TYPE_MISMATCH"),
        ("unauthenticated_human", "UNAUTHENTICATED_OR_NON_HUMAN_APPROVER"),
    ],
)
def test_approval_security_boundaries_fail_closed(
    scenario: str,
    expected_code: str,
    fixed_clock: FixedClock,
    route_registry: RouteFlagRegistry,
) -> None:
    inc_id = "inc_appr_sec_01"
    prop = make_proposal(incident_id=inc_id, created_at=fixed_clock.now())
    inc = make_incident(
        state=IncidentState.AWAITING_APPROVAL,
        incident_id=inc_id,
        proposal=prop,
    )
    fs = make_feature_state(enabled=True, observed_at=fixed_clock.now())
    appr = make_approval(prop, decided_at=fixed_clock.now())
    producer = make_producer(ActorType.HUMAN_OPERATOR)
    event_actor_type = ActorType.HUMAN_OPERATOR
    consumed: set[str] = set()
    active_prop = prop

    if scenario == "missing_approval":
        appr = None  # type: ignore[assignment]
    elif scenario == "rejected_decision":
        appr = make_approval(
            prop,
            decided_at=fixed_clock.now(),
            decision=ApprovalStatus.REJECTED,
            rejection_reason="Rejected by operator",
        )
    elif scenario == "expired_approval":
        fixed_clock.advance(1200)
    elif scenario == "wrong_proposal_id":
        appr = make_approval(prop, decided_at=fixed_clock.now(), proposal_id=generate_proposal_id())
    elif scenario == "wrong_proposal_hash":
        appr = make_approval(prop, decided_at=fixed_clock.now(), proposal_hash="e" * 64)
    elif scenario == "wrong_environment":
        active_prop = make_proposal(
            incident_id=inc_id, created_at=fixed_clock.now(), environment="production"
        )
        inc = make_incident(
            state=IncidentState.AWAITING_APPROVAL,
            incident_id=inc_id,
            environment="production",
            proposal=active_prop,
        )
        appr = make_approval(active_prop, decided_at=fixed_clock.now())
    elif scenario == "unknown_feature":
        active_prop = make_proposal(
            incident_id=inc_id, created_at=fixed_clock.now(), flag_name="undeclared_flag"
        )
        inc = make_incident(
            state=IncidentState.AWAITING_APPROVAL,
            incident_id=inc_id,
            mapped_flag_name="undeclared_flag",
            proposal=active_prop,
        )
        appr = make_approval(active_prop, decided_at=fixed_clock.now())
    elif scenario == "superseded_proposal":
        inc = inc.model_copy(
            update={
                "current_proposal_id": generate_proposal_id(),
                "superseded_proposal_ids": (prop.proposal_id,),
            }
        )
    elif scenario == "consumed_approval":
        consumed.add(appr.approval_id)
    elif scenario == "feature_state_drifted":
        fs = make_feature_state(enabled=False, observed_at=fixed_clock.now())
    elif scenario == "ai_self_approval":
        producer = make_producer(ActorType.AI_AGENT)
        event_actor_type = ActorType.AI_AGENT
    elif scenario == "unauthenticated_human":
        producer = make_producer(ActorType.HUMAN_OPERATOR, authenticated=False)

    evt = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.APPROVAL_GRANTED,
        actor=producer.producer_id,
        actor_type=event_actor_type,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        causation_id=inc.latest_event_id,
        evidence_ids=active_prop.evidence_ids,
        timestamp_utc=fixed_clock.now(),
    )
    ctx = TransitionContext(
        producer_context=producer,
        clock=fixed_clock,
        route_registry=route_registry,
        active_proposal=active_prop,
        approval_decision=appr,
        feature_state=fs,
        consumed_approval_ids=consumed,
        existing_evidence_ids=set(active_prop.evidence_ids),
    )
    _, results = validate_transition(inc, evt, ctx)
    failures = [r for r in results if not r.allowed]
    assert failures, f"Scenario {scenario} unexpectedly passed!"
    if scenario == "ai_self_approval":
        assert any(
            f.reason_code
            in (
                "ACTOR_TYPE_MISMATCH",
                "UNAUTHORIZED_PRODUCER_TYPE",
                "UNAUTHENTICATED_OR_NON_HUMAN_APPROVER",
            )
            for f in failures
        )
    else:
        assert any(f.reason_code == expected_code for f in failures), (
            f"Expected {expected_code}, got {[f.reason_code for f in failures]}"
        )


@pytest.mark.unit
def test_approval_cannot_be_reused_across_rollout_stages(
    fixed_clock: FixedClock, route_registry: RouteFlagRegistry
) -> None:
    inc = make_incident(state=IncidentState.ROLLOUT_PENDING)
    inc = inc.model_copy(
        update={
            "current_rollout_stage": "rstage_0002",
            "consumed_approval_ids": ("appr_stage_1",),
        }
    )
    reused_appr = make_approval(
        make_proposal(incident_id=inc.incident_id, created_at=fixed_clock.now()),
        decided_at=fixed_clock.now(),
        proposal_id="rstage_0002",
        expires_at=fixed_clock.now() + timedelta(minutes=10),
    ).model_copy(update={"approval_id": "appr_stage_1"})

    evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.ROLLOUT_STAGE_APPROVED,
        actor="secops",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    ctx = TransitionContext(
        producer_context=make_producer(ActorType.HUMAN_OPERATOR),
        clock=fixed_clock,
        route_registry=route_registry,
        stage_approval_decision=reused_appr,
    )
    _, results = validate_transition(inc, evt, ctx)
    assert any(f.reason_code == "APPROVAL_ALREADY_CONSUMED" for f in results if not f.allowed)
