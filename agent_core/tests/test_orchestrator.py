"""Integration tests for IncidentOrchestrator, wrapper APIs, and injected adapters."""

from __future__ import annotations

import pytest
from agent_core.adapters.fixtures import (
    FixtureContainmentStrategistAdapter,
    FixtureFeatureMapperAdapter,
    FixtureInvestigatorAdapter,
)
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.orchestrator import IncidentOrchestrator, analyze_incident, on_incident_event
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.tests.conftest import make_feature_state, make_finding, make_producer
from shared.config import load_dependency_graph, load_route_registry
from shared.enums import ActorType, EventType, EvidenceProvenance, FindingStatus, IncidentState
from shared.exceptions import ContractValidationError, InvalidTransitionError
from shared.schemas import FeatureState, Finding, MappingResult, RouteFlagRegistry


@pytest.mark.integration
async def test_orchestrator_on_incident_event_and_analyze_incident_composition(
    fixed_clock: FixedClock,
) -> None:
    repo = InMemoryOrchestrationRepository()
    registry = load_route_registry()
    dep_graph = load_dependency_graph()
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=registry,
        clock=fixed_clock,
        fixture_mode=True,
        investigator=FixtureInvestigatorAdapter(),
        feature_mapper=FixtureFeatureMapperAdapter(),
        containment_strategist=FixtureContainmentStrategistAdapter(clock=fixed_clock),
    )
    finding = make_finding(
        incident_id="inc_orch_001",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_orch_001"],
    )
    inc = await orch.create_incident(
        finding,
        make_producer(ActorType.SECURITY_SCANNER, provenance_mode="fixture"),
    )
    assert inc.current_state == IncidentState.RECEIVED
    assert await orch.get_pending_action(inc.incident_id) == "request_vulnerability_verification"

    p_eng = make_producer(ActorType.DETERMINISTIC_ENGINE, provenance_mode="fixture")
    evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.VERIFICATION_REQUESTED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        timestamp_utc=fixed_clock.now(),
    )
    emitted = await on_incident_event(
        evt,
        orchestrator=orch,
        producer_context=p_eng,
        transition_context=TransitionContext(
            producer_context=p_eng, clock=fixed_clock, fixture_mode=True, finding=finding
        ),
    )
    assert len(emitted) == 1
    updated = await orch.get_incident(inc.incident_id)
    assert updated is not None and updated.current_state == IncidentState.VALIDATION_REQUESTED

    # Invalid event through on_incident_event raises InvalidTransitionError
    bad_evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.APPROVAL_GRANTED,
        actor="secops",
        actor_type=ActorType.HUMAN_OPERATOR,
        sequence_number=3,
        correlation_id=inc.correlation_id,
        causation_id=evt.event_id,
        timestamp_utc=fixed_clock.now(),
    )
    with pytest.raises(InvalidTransitionError):
        await on_incident_event(
            bad_evt,
            orchestrator=orch,
            producer_context=make_producer(ActorType.HUMAN_OPERATOR, provenance_mode="fixture"),
        )

    # analyze_incident composes injected mapper + strategist and validates canonical hash
    proposal = await analyze_incident(
        finding,
        {
            "dependency_graph": dep_graph,
            "observed_features": [make_feature_state(enabled=True)],
        },
        orchestrator=orch,
    )
    assert proposal.flag_name == "search_v1"
    assert proposal.verify_hash() is True


@pytest.mark.unit
async def test_orchestrator_rejects_invalid_injected_ai_output(
    fixed_clock: FixedClock, route_registry: RouteFlagRegistry
) -> None:
    class BadMapper:
        async def map_finding_to_flag(
            self,
            finding: Finding,
            registry: RouteFlagRegistry,
            observed_features: list[FeatureState],
        ) -> MappingResult:
            from shared.enums import MappingStatus
            from shared.schemas import MappingResult

            return MappingResult(
                finding_id="fnd_wrong_id",
                mapping_status=MappingStatus.MATCHED,
                affected_route="/search",
                matched_component="search_service",
                candidate_flags=["search_v1"],
                selected_flag="search_v1",
                registry_version=registry.registry_version,
                mapping_rationale="Wrong finding ID",
            )

    orch = IncidentOrchestrator(
        route_registry=route_registry,
        clock=fixed_clock,
        feature_mapper=BadMapper(),
    )
    finding = make_finding(incident_id="inc_bad_ai_01")
    with pytest.raises(ContractValidationError):
        await orch.run_mapping(finding, [])
