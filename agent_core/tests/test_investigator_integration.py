"""Category L tests: end-to-end IncidentOrchestrator investigation & guard enforcement."""

from __future__ import annotations

import pytest
from agent_core.context import FixedClock, InvestigatorAgent, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.intelligence.investigation_context import InvestigationInputBundle
from agent_core.investigator import Investigator
from agent_core.llm.providers.fixture import FixtureBehaviorMode
from agent_core.llm_client import build_default_gateway
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FindingStatus,
    IncidentState,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.identifiers import utc_now
from shared.schemas import ArtifactReference, Finding, InvestigationSummary, VerificationResult
from shared.serialization import sha256_text


def _setup_finding_and_art(
    incident_id: str, *, status: FindingStatus
) -> tuple[Finding, ArtifactReference, bytes]:
    raw = b"verification output trace"
    art = ArtifactReference(
        artifact_id=f"art_{incident_id}",
        incident_id=incident_id,
        artifact_type=(
            ArtifactType.REPRODUCTION_LOG
            if status == FindingStatus.REPRODUCED
            else ArtifactType.SCANNER_REPORT
        ),
        content_hash=sha256_text(raw.decode("utf-8")),
        storage_ref=f"artifacts/{incident_id}/log.txt",
        producer="verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(raw),
        source_revision="rev_int_01",
    )
    finding = Finding(
        finding_id=f"fnd_{incident_id}",
        incident_id=incident_id,
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=status,
        evidence_ids=[art.artifact_id],
        repository_revision="rev_int_01",
        environment="staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    return finding, art, raw


@pytest.mark.integration
async def test_orchestrator_investigation_on_suspected_finding_cannot_bypass_repro_guard() -> None:
    clock = FixedClock(utc_now())
    repo = InMemoryOrchestrationRepository()
    inv = Investigator(llm_gateway=build_default_gateway())
    orch = IncidentOrchestrator(
        repository=repo, clock=clock, fixture_mode=True, investigator=inv
    )

    finding, art, raw = _setup_finding_and_art("inc_int_susp", status=FindingStatus.SUSPECTED)
    await repo.store_artifact(art, raw)

    scan_prod = ProducerContext(
        producer_id="scanner",
        actor_type=ActorType.SECURITY_SCANNER,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    inc = await orch.create_incident(finding, scan_prod)
    summary, _, res = await orch.execute_investigation(
        finding=finding, producer_context=eng_prod, evidence_artifacts=[art]
    )
    assert res.accepted is True
    assert summary.finding_status == FindingStatus.SUSPECTED
    # Remains in RECEIVED; cannot skip into REPRODUCED or FLAG_MAPPED
    updated = await orch.get_incident(inc.incident_id)
    assert updated is not None
    assert updated.current_state == IncidentState.RECEIVED
    assert updated.investigation_id == summary.investigation_id

    # Attempted FLAG_MAPPED without passing through REPRODUCED MUST STILL FAIL
    bad_map_evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.FLAG_MAPPED,
        actor="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=updated.latest_event_sequence + 1,
        correlation_id=inc.correlation_id,
        evidence_ids=[art.artifact_id],
        timestamp_utc=clock.now(),
    )
    map_res = await orch.process_event(bad_map_evt, producer_context=eng_prod)
    assert map_res.accepted is False


@pytest.mark.integration
async def test_orchestrator_reproduced_finding_records_completed_event_and_fallback() -> None:
    clock = FixedClock(utc_now())
    repo = InMemoryOrchestrationRepository()
    # Force fallback via timeout to verify orchestrator records fallback metadata cleanly
    inv = Investigator(llm_gateway=build_default_gateway(fixture_mode=FixtureBehaviorMode.TIMEOUT))
    orch = IncidentOrchestrator(
        repository=repo, clock=clock, fixture_mode=True, investigator=inv
    )

    finding, art, raw = _setup_finding_and_art("inc_int_repro", status=FindingStatus.REPRODUCED)
    await repo.store_artifact(art, raw)
    scan_prod = ProducerContext(
        producer_id="scanner",
        actor_type=ActorType.SECURITY_SCANNER,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    ver_prod = ProducerContext(
        producer_id="verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    inc = await orch.create_incident(finding, scan_prod)
    await orch.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.VERIFICATION_REQUESTED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=2,
            correlation_id=inc.correlation_id,
            timestamp_utc=clock.now(),
        ),
        producer_context=eng_prod,
    )
    ver = VerificationResult(
        verification_id="ver_int_1",
        incident_id=inc.incident_id,
        test_id="t_sqli",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        expected_revision="rev_int_01",
        tested_revision="rev_int_01",
        artifact_ids=[art.artifact_id],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    await orch.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.REPRODUCTION_CONFIRMED,
            actor="verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id=inc.correlation_id,
            evidence_ids=[art.artifact_id],
            timestamp_utc=clock.now(),
        ),
        producer_context=ver_prod,
        transition_context=TransitionContext(
            producer_context=ver_prod,
            clock=clock,
            fixture_mode=True,
            verification_result=ver,
        ),
    )

    bundle = InvestigationInputBundle(
        finding=finding, evidence_artifacts=[art], verification_results=[ver]
    )
    summary, _, inv_res = await orch.execute_investigation(
        finding=finding, producer_context=eng_prod, bundle=bundle
    )
    assert inv_res.accepted is True
    assert summary.fallback_used is True
    assert summary.recommended_next_action == "request_feature_mapping"

    events = await orch.get_incident_events(inc.incident_id)
    evt_types = [e.event_type for e in events]
    assert EventType.INVESTIGATION_REQUESTED in evt_types
    assert EventType.INVESTIGATION_COMPLETED in evt_types


@pytest.mark.integration
async def test_orchestrator_rejects_cheating_investigator_promoting_status() -> None:
    class BadInvestigator(InvestigatorAgent):
        async def investigate(
            self, finding: Finding, evidence_artifacts: list[ArtifactReference]
        ) -> InvestigationSummary:
            return InvestigationSummary(
                investigation_id="inv_bad_01",
                finding_id=finding.finding_id,
                incident_id=finding.incident_id,
                executive_summary="Hijacked status promotion",
                technical_explanation="Claiming reproduced falsely",
                finding_status=FindingStatus.REPRODUCED,
                recommended_next_action="request_feature_mapping",
            )

    repo = InMemoryOrchestrationRepository()
    orch = IncidentOrchestrator(
        repository=repo,
        clock=FixedClock(utc_now()),
        fixture_mode=True,
        investigator=BadInvestigator(),
    )
    finding, art, raw = _setup_finding_and_art("inc_bad_inv", status=FindingStatus.SUSPECTED)
    await repo.store_artifact(art, raw)
    scan_prod = ProducerContext(
        producer_id="scanner",
        actor_type=ActorType.SECURITY_SCANNER,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    await orch.create_incident(finding, scan_prod)
    with pytest.raises(ContractValidationError):
        await orch.execute_investigation(
            finding=finding, producer_context=eng_prod, evidence_artifacts=[art]
        )
    events = await orch.get_incident_events(finding.incident_id)
    assert events[-1].event_type == EventType.INVESTIGATION_FAILED
