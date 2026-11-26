"""Tests for orchestrator mapping integration, security contract compat, demos, and eval."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from agent_core.adapters.security_contract import (
    normalize_security_finding,
    normalize_security_verification_result,
)
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.demos.mapping_demos import run_mapping_demos
from agent_core.evaluations.mapping_evaluator import run_mapping_evaluation
from agent_core.events import build_incident_event
from agent_core.flag_mapper import DeterministicFlagMapper
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.replay import replay_incident
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.config import load_route_registry
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    IncidentState,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.identifiers import generate_incident_id
from shared.schemas import ArtifactReference, FeatureState, Finding
from shared.serialization import sha256_text

NOW = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)


async def _setup_reproduced_incident(
    *,
    route: str | None = "/files",
    component: str = "file_service",
    status: FindingStatus = FindingStatus.REPRODUCED,
) -> tuple[IncidentOrchestrator, InMemoryOrchestrationRepository, Finding, ProducerContext]:
    reg = load_route_registry()
    repo = InMemoryOrchestrationRepository()
    clock = FixedClock(NOW)
    mapper = DeterministicFlagMapper(evidence_repository=repo, clock=clock, fixture_mode=True)
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=reg,
        clock=clock,
        fixture_mode=True,
        feature_mapper=mapper,
    )
    inc_id = generate_incident_id()
    raw = b"reproduction proof"
    art = ArtifactReference(
        artifact_id="art_orch_map_01",
        incident_id=inc_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash=sha256_text(raw.decode("utf-8")),
        storage_ref="repro/orch.log",
        created_at=NOW,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(raw),
        source_revision=reg.application_revision,
    )
    await repo.store_artifact(art, raw)
    finding = Finding(
        finding_id="fnd_orch_map_01",
        incident_id=inc_id,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        affected_route=route,
        affected_component=component,
        severity=VulnerabilitySeverity.HIGH,
        status=status,
        evidence_ids=[art.artifact_id] if status == FindingStatus.REPRODUCED else [],
        repository_revision=reg.application_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
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
    inc = await orch.create_incident(finding, sys_prod)
    if status == FindingStatus.REPRODUCED:
        await orch.process_event(
            build_incident_event(
                incident_id=inc.incident_id,
                event_type=EventType.VERIFICATION_REQUESTED,
                actor="deterministic_engine",
                actor_type=ActorType.DETERMINISTIC_ENGINE,
                sequence_number=2,
                correlation_id=inc.correlation_id,
                timestamp_utc=NOW,
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
                evidence_ids=[art.artifact_id],
                timestamp_utc=NOW,
            ),
            producer_context=ver_prod,
            transition_context=TransitionContext(
                producer_context=ver_prod,
                clock=clock,
                fixture_mode=True,
            ),
        )
    return orch, repo, finding, eng_prod


@pytest.mark.asyncio
async def test_orchestrator_execute_mapping_matched_and_replay() -> None:
    orch, repo, finding, eng_prod = await _setup_reproduced_incident()
    fs = FeatureState(
        environment="demo-staging",
        feature_id="fs_files_v1",
        feature_name="files_v1",
        observation_status=FeatureObservationStatus.OBSERVED,
        enabled=True,
        observed_at=NOW,
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    outcome, evt_res = await orch.execute_mapping(
        finding=finding,
        producer_context=eng_prod,
        observed_features=[fs],
    )
    assert outcome.mapping_result.selected_flag == "files_v1"
    assert evt_res.accepted is True
    assert evt_res.current_state == IncidentState.FLAG_MAPPED

    events = await repo.list_incident_events(finding.incident_id)
    assert any(e.event_type == EventType.MAPPING_REQUESTED for e in events)
    assert any(e.event_type == EventType.MAPPING_MATCHED for e in events)

    replayed = replay_incident(events)
    assert replayed.current_state == IncidentState.FLAG_MAPPED


@pytest.mark.asyncio
async def test_orchestrator_execute_mapping_unmapped_and_suspected_rejected() -> None:
    orch, _repo, finding, eng_prod = await _setup_reproduced_incident(
        route="/unknown", component="unknown_svc"
    )
    outcome, evt_res = await orch.execute_mapping(
        finding=finding,
        producer_context=eng_prod,
        observed_features=[],
    )
    assert outcome.mapping_result.selected_flag is None
    assert evt_res.current_state == IncidentState.UNMAPPED

    orch_sus, _repo_sus, f_sus, eng_sus = await _setup_reproduced_incident(
        status=FindingStatus.SUSPECTED
    )
    with pytest.raises(ContractValidationError):
        await orch_sus.execute_mapping(finding=f_sus, producer_context=eng_sus)


def test_security_contract_normalization() -> None:
    finding, extras = normalize_security_finding(
        {
            "finding_id": "fnd_sec_01",
            "incident_id": "inc_sec_01",
            "category": "sqli",
            "affected_route": "/legacy/search",
            "affected_component": "search_v1",
            "severity": "high",
            "status": "reproduced",
            "evidence_id": "ev-sqli-1234",
            "revision": "abc123",
            "test_id": "sqli_search",
        }
    )
    assert finding.category == VulnerabilityCategory.SQL_INJECTION
    assert finding.affected_component == "search_v1"
    assert finding.repository_revision == "abc123"
    assert extras["source_scanner_known"] is False

    # Infrastructure error with passed=False in security payload normalizes to passed=None
    vr_infra = normalize_security_verification_result(
        {
            "verification_id": "ver_sec_01",
            "incident_id": "inc_sec_01",
            "test_id": "sqli_search",
            "phase": "before",
            "outcome": "infrastructure_error",
            "passed": False,
            "requested_revision": "rev1",
            "revision": "rev1",
        }
    )
    assert vr_infra.phase == VerificationPhase.BEFORE_CONTAINMENT
    assert vr_infra.execution_status == TestExecutionStatus.INFRASTRUCTURE_ERROR
    assert vr_infra.passed is None

    # Smoke-test failure is NOT converted to successful containment
    vr_smoke = normalize_security_verification_result(
        {
            "verification_id": "ver_sec_02",
            "incident_id": "inc_sec_01",
            "test_id": "sqli_search",
            "phase": "after_containment",
            "outcome": "contained_smoke_failed",
            "passed": False,
        }
    )
    assert vr_smoke.execution_status == TestExecutionStatus.TEST_FAILED
    assert vr_smoke.passed is False


@pytest.mark.asyncio
async def test_mapping_demos_and_evaluation(tmp_path: Path) -> None:
    demos = await run_mapping_demos()
    assert len(demos) == 10
    report = await run_mapping_evaluation(reports_dir=tmp_path)
    assert report["failed_cases"] == 0
    assert report["unsafe_operational_eligibility_count"] == 0
    assert report["incorrect_feature_rejected"] is True
