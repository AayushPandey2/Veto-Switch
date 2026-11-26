"""Category B: Transition guard & fail-closed evidence/unknown-info tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.state_machine import validate_transition
from agent_core.tests.conftest import (
    make_approval,
    make_feature_state,
    make_finding,
    make_incident,
    make_producer,
    make_proposal,
)
from shared.enums import (
    ActorType,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    IncidentState,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.identifiers import generate_artifact_id, generate_test_run_id, generate_verification_id
from shared.schemas import RouteFlagRegistry, VerificationResult


@pytest.mark.unit
def test_guard_rejects_unauthenticated_producer_and_mismatched_incident(
    fixed_clock: FixedClock, route_registry: RouteFlagRegistry
) -> None:
    inc = make_incident(state=IncidentState.RECEIVED)
    evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="spoofed_engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    unauth_ctx = TransitionContext(
        producer_context=make_producer(ActorType.DETERMINISTIC_ENGINE, authenticated=False),
        clock=fixed_clock,
        route_registry=route_registry,
    )
    _, results = validate_transition(inc, evt, unauth_ctx)
    failures = [r for r in results if not r.allowed]
    assert any(f.reason_code == "UNAUTHENTICATED_PRODUCER" for f in failures)

    wrong_inc_evt = evt.model_copy(update={"incident_id": "inc_wrong_0001"})
    auth_ctx = TransitionContext(
        producer_context=make_producer(ActorType.DETERMINISTIC_ENGINE),
        clock=fixed_clock,
        route_registry=route_registry,
    )
    _, results2 = validate_transition(inc, wrong_inc_evt, auth_ctx)
    assert any(f.reason_code == "INCIDENT_ID_MISMATCH" for f in results2 if not f.allowed)


@pytest.mark.unit
def test_guard_rejects_unknown_feature_state_and_missing_smoke_test(
    fixed_clock: FixedClock, route_registry: RouteFlagRegistry
) -> None:
    prop = make_proposal(incident_id="inc_guard_001", created_at=fixed_clock.now())
    inc = make_incident(
        state=IncidentState.AWAITING_APPROVAL,
        incident_id="inc_guard_001",
        proposal=prop,
    )
    appr = make_approval(prop)
    evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.APPROVAL_GRANTED,
        actor="secops_operator",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        causation_id=inc.latest_event_id,
        evidence_ids=prop.evidence_ids,
        timestamp_utc=fixed_clock.now() + timedelta(seconds=20),
    )
    unknown_fs = make_feature_state(
        enabled=None, observation_status=FeatureObservationStatus.UNKNOWN
    )
    ctx = TransitionContext(
        producer_context=make_producer(ActorType.HUMAN_OPERATOR),
        clock=fixed_clock,
        route_registry=route_registry,
        active_proposal=prop,
        approval_decision=appr,
        feature_state=unknown_fs,
        existing_evidence_ids=set(prop.evidence_ids),
    )
    _, results = validate_transition(inc, evt, ctx)
    failures = [r for r in results if not r.allowed]
    assert any(f.reason_code == "UNKNOWN_FEATURE_STATE" for f in failures)

    # Post-containment requires BOTH passing security regression AND functional smoke test
    art = generate_artifact_id()
    inc_cont = make_incident(
        state=IncidentState.CONTAINMENT_TEST_PENDING,
        incident_id="inc_guard_002",
        last_op_ts=fixed_clock.now(),
    )
    vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=inc_cont.incident_id,
        test_id="sqli_after",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        expected_revision="rev_abc123",
        tested_revision="rev_abc123",
        artifact_ids=[art],
        started_at=fixed_clock.now() + timedelta(seconds=1),
        completed_at=fixed_clock.now() + timedelta(seconds=5),
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    evt_cont = build_incident_event(
        incident_id=inc_cont.incident_id,
        event_type=EventType.CONTAINMENT_CONFIRMED,
        actor="verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        sequence_number=2,
        correlation_id=inc_cont.correlation_id,
        causation_id=inc_cont.latest_event_id,
        evidence_ids=[art],
        timestamp_utc=fixed_clock.now() + timedelta(seconds=6),
    )
    ctx_no_smoke = TransitionContext(
        producer_context=make_producer(ActorType.SECURITY_VERIFIER),
        clock=fixed_clock,
        verification_result=vr,
        feature_state=make_feature_state(
            enabled=False, observed_at=fixed_clock.now() + timedelta(seconds=3)
        ),
        functional_smoke_passed=None,
        existing_evidence_ids={art},
    )
    _, cont_results = validate_transition(inc_cont, evt_cont, ctx_no_smoke)
    assert any(
        f.reason_code == "MISSING_OR_FAILED_SMOKE_TEST" for f in cont_results if not f.allowed
    )


@pytest.mark.unit
def test_live_mode_rejects_fixture_provenance_evidence(fixed_clock: FixedClock) -> None:
    inc = make_incident(state=IncidentState.VALIDATION_REQUESTED)
    art = generate_artifact_id()
    vr_fixture = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=inc.incident_id,
        test_id="sqli",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        expected_revision="rev_abc123",
        tested_revision="rev_abc123",
        artifact_ids=[art],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.REPRODUCTION_CONFIRMED,
        actor="verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        evidence_ids=[art],
        timestamp_utc=fixed_clock.now(),
    )
    ctx_live = TransitionContext(
        producer_context=make_producer(ActorType.SECURITY_VERIFIER, provenance_mode="live"),
        clock=fixed_clock,
        fixture_mode=False,
        finding=make_finding(incident_id=inc.incident_id, finding_id=inc.finding_id),
        verification_result=vr_fixture,
        existing_evidence_ids={art},
    )
    _, results = validate_transition(inc, evt, ctx_live)
    assert any(
        f.reason_code == "UNTRUSTED_PROVENANCE_IN_LIVE_MODE" for f in results if not f.allowed
    )
