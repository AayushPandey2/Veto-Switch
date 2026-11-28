"""Runnable offline demonstrations (Demos A-J) for Phase 05 Blast Radius & Containment."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from shared.config import load_dependency_graph, load_route_registry
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    MappingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import generate_incident_id
from shared.schemas import ArtifactReference, FeatureState, Finding, MappingResult
from shared.serialization import sha256_text

from agent_core.containment.dashboard import serialize_containment_dashboard
from agent_core.containment_strategist import DeterministicContainmentStrategist
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.flag_mapper import DeterministicFlagMapper
from agent_core.mapping.models import MappingContext
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository


def _obs(flag: str, *, enabled: bool, now: datetime) -> FeatureState:
    return FeatureState(
        environment="demo-staging",
        feature_id=f"fs_{flag}",
        feature_name=flag,
        observation_status=FeatureObservationStatus.OBSERVED,
        enabled=enabled,
        observed_at=now,
        state_version="v1",
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
    )


async def run_blast_radius_demos() -> list[dict[str, Any]]:
    """Execute offline Phase 05 blast-radius & containment demonstrations A-J."""
    now = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)
    clock = FixedClock(now)
    registry = load_route_registry()
    graph = load_dependency_graph()
    mapper = DeterministicFlagMapper(clock=clock, fixture_mode=True)
    strategist = DeterministicContainmentStrategist(
        clock=clock, registry=registry, fixture_mode=True
    )
    outputs: list[dict[str, Any]] = []

    f_search = Finding(
        finding_id="fnd_br_demo_search",
        incident_id="inc_br_demo_search",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_br_demo_01"],
        repository_revision=registry.application_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    states_search = [
        _obs("search_v1", enabled=True, now=now),
        _obs("search_v2", enabled=False, now=now),
    ]
    map_search = await mapper.map_finding_to_flag(
        f_search,
        registry,
        states_search,
        context=MappingContext(
            finding=f_search,
            observed_implementation="search_v1",
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=now,
        ),
    )

    # Demo A & B & C & D & G — Search containment vs replacement vs broad shutdown
    analysis_a = await strategist.analyze_containment(
        f_search, map_search, graph, states_search
    )
    dash_a = serialize_containment_dashboard(analysis_a, graph)
    outputs.append({"demo": "Phase 05 Demo A/B/C/D/G (Search Containment)", **dash_a})

    # Demo E — Already-disabled feature
    states_disabled = [_obs("search_v1", enabled=False, now=now)]
    map_disabled = await mapper.map_finding_to_flag(
        f_search,
        registry,
        states_disabled,
        context=MappingContext(
            finding=f_search,
            observed_implementation="search_v1",
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=now,
        ),
    )
    analysis_e = await strategist.analyze_containment(
        f_search, map_disabled, graph, states_disabled
    )
    outputs.append(
        {
            "demo": "Phase 05 Demo E (Already Disabled)",
            "manual_review_required": analysis_e.manual_review_required,
            "proposal_created": analysis_e.proposal is not None,
            "verification_checklist": analysis_e.verification_checklist,
        }
    )

    # Demo F — No safe strategy (stale state)
    states_stale = [_obs("search_v1", enabled=True, now=now - timedelta(hours=2))]
    analysis_f = await strategist.analyze_containment(
        f_search, map_search, graph, states_stale
    )
    outputs.append(
        {
            "demo": "Phase 05 Demo F (No Safe Strategy - Stale State)",
            "manual_review_required": analysis_f.manual_review_required,
            "proposal_created": analysis_f.proposal is not None,
            "reason_codes": [c.value for c in analysis_f.reason_codes],
        }
    )

    # Demo H & J — Full offline Agent 1 integration stopping at AWAITING_APPROVAL
    repo = InMemoryOrchestrationRepository()
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=registry,
        clock=clock,
        fixture_mode=True,
        feature_mapper=DeterministicFlagMapper(
            evidence_repository=repo, clock=clock, fixture_mode=True
        ),
        containment_strategist=strategist,
    )
    inc_id = generate_incident_id()
    art_bytes = b"reproduction proof"
    art_ref = ArtifactReference(
        artifact_id="art_br_demo_j",
        incident_id=inc_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash=sha256_text(art_bytes.decode("utf-8")),
        storage_ref="repro/br_j.log",
        created_at=now,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(art_bytes),
        source_revision=registry.application_revision,
    )
    await repo.store_artifact(art_ref, art_bytes)
    f_j = f_search.model_copy(
        update={
            "finding_id": "fnd_br_demo_j",
            "incident_id": inc_id,
            "evidence_ids": [art_ref.artifact_id],
        }
    )
    sys_prod = ProducerContext(
        producer_id="platform_api",
        actor_type=ActorType.SYSTEM,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="deterministic_engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    ver_prod = ProducerContext(
        producer_id="authorized_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    inc = await orch.create_incident(f_j, sys_prod)
    await orch.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.VERIFICATION_REQUESTED,
            actor="deterministic_engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=2,
            correlation_id=inc.correlation_id,
            timestamp_utc=now,
        ),
        producer_context=eng_prod,
    )
    await orch.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.REPRODUCTION_CONFIRMED,
            actor="authorized_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id=inc.correlation_id,
            evidence_ids=[art_ref.artifact_id],
            timestamp_utc=now,
        ),
        producer_context=ver_prod,
        transition_context=TransitionContext(
            producer_context=ver_prod, clock=clock, fixture_mode=True
        ),
    )
    map_out, _ = await orch.execute_mapping(
        finding=f_j,
        producer_context=eng_prod,
        observed_features=states_search,
        mapping_context=MappingContext(
            finding=f_j,
            observed_implementation="search_v1",
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=now,
        ),
    )
    cont_analysis, cont_res = await orch.execute_containment_analysis(
        finding=f_j,
        mapping=map_out.mapping_result,
        dependency_graph=graph,
        observed_features=states_search,
        producer_context=eng_prod,
    )
    outputs.append(
        {
            "demo": "Phase 05 Demo H/J (Orchestrator E2E -> AWAITING_APPROVAL)",
            "incident_id": inc.incident_id,
            "final_state": cont_res.current_state.value if cont_res.current_state else None,
            "proposal_flag": (
                cont_analysis.proposal.flag_name
                if cont_analysis and cont_analysis.proposal
                else None
            ),
            "pending_executions": len(cont_res.pending_requests),
        }
    )

    # Demo I — Determinism (reversed graph)
    rev_graph = graph.model_copy(
        update={
            "nodes": list(reversed(graph.nodes)),
            "edges": list(reversed(graph.edges)),
        }
    )
    analysis_rev = await strategist.analyze_containment(
        f_search, map_search, rev_graph, list(reversed(states_search))
    )
    rec_a = analysis_a.recommended_option
    rec_rev = analysis_rev.recommended_option
    outputs.append(
        {
            "demo": "Phase 05 Demo I (Determinism)",
            "same_winner": (
                (rec_a.proposed_target if rec_a else None)
                == (rec_rev.proposed_target if rec_rev else None)
            ),
            "same_score": (
                (rec_a.relative_policy_score if rec_a else None)
                == (rec_rev.relative_policy_score if rec_rev else None)
            ),
        }
    )
    _ = MappingStatus
    _ = MappingResult
    return outputs


def main() -> int:
    for item in asyncio.run(run_blast_radius_demos()):
        print(f"[BLAST RADIUS DEMO] {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
