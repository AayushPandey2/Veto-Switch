"""Category B/J: Evidence repository, hash, incident binding, and trust-boundary tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from agent_core.context import FixedClock, TransitionContext
from agent_core.events import build_incident_event
from agent_core.evidence_validator import EvidenceValidator, validate_artifact_metadata
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.tests.conftest import (
    make_finding,
    make_incident,
    make_producer,
    store_evidence_artifact,
)
from shared.artifacts import build_artifact_reference
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    IncidentState,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.identifiers import generate_test_run_id, generate_verification_id
from shared.schemas import VerificationResult


@pytest.mark.unit
async def test_evidence_validator_checks_existence_incident_binding_and_hash(
    memory_repo: InMemoryOrchestrationRepository, fixed_clock: FixedClock
) -> None:
    validator = EvidenceValidator(memory_repo, clock=fixed_clock, fixture_mode=False)
    inc_a = "inc_evid_0001"
    inc_b = "inc_evid_0002"
    art_id = await store_evidence_artifact(
        memory_repo, incident_id=inc_a, content=b'{"repro": true}'
    )

    ok_res = await validator.verify_artifact_ids_exist(
        incident_id=inc_a,
        evidence_ids=[art_id],
        content_by_id={art_id: b'{"repro": true}'},
    )
    assert ok_res.allowed is True

    # Cross-incident evidence rejected
    cross_res = await validator.verify_artifact_ids_exist(
        incident_id=inc_b,
        evidence_ids=[art_id],
    )
    assert cross_res.allowed is False
    assert cross_res.reason_code == "EVIDENCE_NOT_FOUND"

    # Tampered artifact content rejected
    tampered_res = await validator.verify_artifact_ids_exist(
        incident_id=inc_a,
        evidence_ids=[art_id],
        content_by_id={art_id: b'{"repro": false}'},
    )
    assert tampered_res.allowed is False
    assert tampered_res.reason_code == "ARTIFACT_HASH_MISMATCH"


@pytest.mark.unit
def test_artifact_metadata_rejects_wrong_type_revision_and_future_timestamp(
    fixed_clock: FixedClock,
) -> None:
    inc = make_incident(state=IncidentState.VALIDATION_REQUESTED, source_revision="rev_good")
    ref = build_artifact_reference(
        incident_id=inc.incident_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content=b"log",
        storage_ref="artifacts/log.txt",
        producer="verifier",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        source_revision="rev_wrong",
    )
    res_rev = validate_artifact_metadata(
        ref, incident=inc, expected_revision="rev_good", reference_time=fixed_clock.now()
    )
    assert res_rev.allowed is False
    assert res_rev.reason_code == "ARTIFACT_REVISION_MISMATCH"

    future_ref = ref.model_copy(
        update={
            "source_revision": "rev_good",
            "created_at": fixed_clock.now() + timedelta(minutes=5),
        }
    )
    res_future = validate_artifact_metadata(
        future_ref,
        incident=inc,
        expected_type=ArtifactType.REPRODUCTION_LOG,
        reference_time=fixed_clock.now(),
    )
    assert res_future.allowed is False
    assert res_future.reason_code == "FUTURE_EVIDENCE_TIMESTAMP"


@pytest.mark.integration
async def test_orchestrator_rejects_unregistered_evidence_id_in_event(
    live_orchestrator: IncidentOrchestrator, fixed_clock: FixedClock
) -> None:
    finding = make_finding(incident_id="inc_evid_orch_01")
    inc = await live_orchestrator.create_incident(
        finding, make_producer(ActorType.SECURITY_SCANNER)
    )
    p_eng = make_producer(ActorType.DETERMINISTIC_ENGINE)
    await live_orchestrator.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.VERIFICATION_REQUESTED,
            actor="engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=2,
            correlation_id=inc.correlation_id,
            timestamp_utc=fixed_clock.now(),
        ),
        p_eng,
        TransitionContext(producer_context=p_eng, clock=fixed_clock, finding=finding),
    )

    fake_art_id = "art_does_not_exist_in_repo"
    vr = VerificationResult(
        verification_id=generate_verification_id(),
        incident_id=inc.incident_id,
        test_id="sqli",
        test_run_id=generate_test_run_id(),
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        expected_revision="rev_abc123",
        tested_revision="rev_abc123",
        artifact_ids=[fake_art_id],
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    p_ver = make_producer(ActorType.SECURITY_VERIFIER)
    res = await live_orchestrator.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.REPRODUCTION_CONFIRMED,
            actor="verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id=inc.correlation_id,
            evidence_ids=[fake_art_id],
            timestamp_utc=fixed_clock.now(),
        ),
        p_ver,
        TransitionContext(
            producer_context=p_ver,
            clock=fixed_clock,
            finding=finding,
            verification_result=vr,
        ),
    )
    assert not res.accepted
    assert res.reason_code == "UNKNOWN_OR_CROSS_INCIDENT_EVIDENCE"
    stored = await live_orchestrator.get_incident(inc.incident_id)
    assert stored is not None and stored.current_state == IncidentState.VALIDATION_REQUESTED
