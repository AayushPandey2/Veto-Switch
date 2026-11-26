"""Runnable offline demonstrations (Demos A-J) for Phase 04 Feature Flag Mapping."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from shared.config import load_route_registry
from shared.enums import (
    ActorType,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.identifiers import generate_incident_id
from shared.schemas import ArtifactReference, FeatureState, Finding, MappingResult
from shared.serialization import sha256_text

from agent_core.adapters.security_contract import normalize_security_finding
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.flag_mapper import DeterministicFlagMapper
from agent_core.mapping.dashboard import serialize_mapping_dashboard
from agent_core.mapping.models import MappingContext
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.policies import validate_mapping_output
from agent_core.repositories.memory import InMemoryOrchestrationRepository


def _obs(
    flag_name: str,
    *,
    enabled: bool | None,
    now: datetime,
    status: FeatureObservationStatus = FeatureObservationStatus.OBSERVED,
) -> FeatureState:
    return FeatureState(
        environment="demo-staging",
        feature_id=f"fs_{flag_name}",
        feature_name=flag_name,
        observation_status=status,
        enabled=enabled,
        observed_at=now,
        state_version="v1",
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
    )


async def run_mapping_demos() -> list[dict[str, Any]]:
    """Execute offline Phase 04 mapping demonstrations A-J."""
    now = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)
    clock = FixedClock(now)
    registry = load_route_registry()
    mapper = DeterministicFlagMapper(clock=clock, fixture_mode=True)
    outputs: list[dict[str, Any]] = []

    # Demo A — Correct legacy search mapping (fixture-labeled)
    finding_a = Finding(
        finding_id="fnd_demo_map_a",
        incident_id="inc_demo_map_a",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_demo_map_a"],
        repository_revision=registry.application_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    out_a = await mapper.map_with_diagnostics(
        finding_a,
        registry,
        [_obs("search_v1", enabled=True, now=now), _obs("search_v2", enabled=False, now=now)],
        context=MappingContext(
            finding=finding_a,
            observed_implementation="search_v1",
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=now,
        ),
    )
    outputs.append({"demo": "Mapping Demo A (Search SQLi)", **serialize_mapping_dashboard(out_a)})

    # Demo B — Path traversal mapping
    finding_b = Finding(
        finding_id="fnd_demo_map_b",
        incident_id="inc_demo_map_b",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        affected_route="/files",
        affected_component="file_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_demo_map_b"],
        repository_revision=registry.application_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    out_b = await mapper.map_with_diagnostics(
        finding_b,
        registry,
        [_obs("files_v1", enabled=True, now=now)],
    )
    outputs.append(
        {"demo": "Mapping Demo B (Files Traversal)", **serialize_mapping_dashboard(out_b)}
    )

    # Demo C — Alias resolution (/legacy/search -> /search)
    finding_c = finding_a.model_copy(
        update={"finding_id": "fnd_demo_map_c", "affected_route": "/legacy/search"}
    )
    out_c = await mapper.map_with_diagnostics(
        finding_c,
        registry,
        [_obs("search_v1", enabled=True, now=now)],
        context=MappingContext(
            finding=finding_c,
            observed_implementation="search_v1",
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=now,
        ),
    )
    outputs.append({"demo": "Mapping Demo C (Alias)", **serialize_mapping_dashboard(out_c)})

    # Demo D — Ambiguous mapping (multi-flag route without implementation evidence)
    out_d = await mapper.map_with_diagnostics(
        finding_a,
        registry,
        [_obs("search_v1", enabled=True, now=now), _obs("search_v2", enabled=True, now=now)],
    )
    outputs.append({"demo": "Mapping Demo D (Ambiguous)", **serialize_mapping_dashboard(out_d)})

    # Demo E — Incorrect mapper rejection (files_v1 for /search)
    bad_result = MappingResult(
        finding_id=finding_a.finding_id,
        mapping_status="matched",  # type: ignore[arg-type]
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["files_v1"],
        selected_flag="files_v1",
        registry_version=registry.registry_version,
        mapping_rationale="Simulated buggy mapper selecting wrong flag.",
        evidence_ids=list(finding_a.evidence_ids),
        manual_review_required=False,
    )
    rejected_reason = ""
    try:
        validate_mapping_output(bad_result, finding=finding_a, registry=registry)
    except ContractValidationError as exc:
        rejected_reason = exc.message
    outputs.append(
        {
            "demo": "Mapping Demo E (Incorrect Mapper Rejected)",
            "rejected": bool(rejected_reason),
            "reason": rejected_reason,
        }
    )

    # Demo F — Stale state
    stale_obs = _obs("files_v1", enabled=True, now=now - timedelta(hours=2))
    out_f = await mapper.map_with_diagnostics(finding_b, registry, [stale_obs])
    outputs.append({"demo": "Mapping Demo F (Stale State)", **serialize_mapping_dashboard(out_f)})

    # Demo G — Already-disabled feature
    disabled_obs = _obs("files_v1", enabled=False, now=now)
    out_g = await mapper.map_with_diagnostics(finding_b, registry, [disabled_obs])
    outputs.append(
        {"demo": "Mapping Demo G (Already Disabled)", **serialize_mapping_dashboard(out_g)}
    )

    # Demo H — Unknown route
    finding_h = finding_a.model_copy(
        update={
            "finding_id": "fnd_demo_map_h",
            "affected_route": "/unknown-admin",
            "affected_component": "unknown_service",
        }
    )
    out_h = await mapper.map_with_diagnostics(finding_h, registry, [])
    outputs.append({"demo": "Mapping Demo H (Unknown Route)", **serialize_mapping_dashboard(out_h)})

    # Demo I — Cybersecurity contract compatibility
    sec_finding, sec_extras = normalize_security_finding(
        {
            "finding_id": "fnd_sec_demo_i",
            "incident_id": "inc_sec_demo_i",
            "category": "sqli",
            "affected_route": "/legacy/search",
            "affected_component": "search_v1",
            "severity": "high",
            "status": "reproduced",
            "evidence_id": "ev-sqli-0001",
            "revision": registry.application_revision,
            "test_id": "sqli_search",
        },
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    out_i = await mapper.map_with_diagnostics(
        sec_finding,
        registry,
        [_obs("search_v1", enabled=True, now=now)],
        context=MappingContext(
            finding=sec_finding,
            registered_test_id=sec_extras.get("test_id"),
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=now,
        ),
    )
    outputs.append(
        {
            "demo": "Mapping Demo I (Security Contract)",
            "normalized_category": sec_finding.category.value,
            **serialize_mapping_dashboard(out_i),
        }
    )

    # Demo J — End-to-end offline mapping lifecycle via IncidentOrchestrator
    repo = InMemoryOrchestrationRepository()
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=registry,
        clock=clock,
        fixture_mode=True,
        feature_mapper=mapper,
    )
    inc_id = generate_incident_id()
    art_bytes = b"reproduction-proof"
    art_ref = ArtifactReference(
        artifact_id="art_demo_map_j",
        incident_id=inc_id,
        artifact_type="reproduction_log",  # type: ignore[arg-type]
        content_hash=sha256_text(art_bytes.decode("utf-8")),
        storage_ref="repro/demo_j.log",
        created_at=now,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(art_bytes),
        source_revision=registry.application_revision,
    )
    await repo.store_artifact(art_ref, art_bytes)
    finding_j = finding_b.model_copy(
        update={
            "finding_id": "fnd_demo_map_j",
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
    ver_prod = ProducerContext(
        producer_id="authorized_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
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
    inc = await orch.create_incident(finding_j, sys_prod)
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
            producer_context=ver_prod,
            clock=clock,
            fixture_mode=True,
        ),
    )
    out_j, evt_res_j = await orch.execute_mapping(
        finding=finding_j,
        producer_context=eng_prod,
        observed_features=[_obs("files_v1", enabled=True, now=now)],
    )
    outputs.append(
        {
            "demo": "Mapping Demo J (Orchestrator E2E)",
            "incident_id": inc.incident_id,
            "final_state": evt_res_j.current_state.value if evt_res_j.current_state else None,
            "selected_flag": out_j.mapping_result.selected_flag,
        }
    )
    return outputs


def main() -> int:
    for item in asyncio.run(run_mapping_demos()):
        print(f"[MAPPING DEMO] {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
