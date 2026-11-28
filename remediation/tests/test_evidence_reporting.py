"""Tests for Phase 11 Incident Evidence Intelligence, redaction, bundles, and orchestration."""

from __future__ import annotations

import json
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from agent_core.context import EventProcessingResult
from agent_core.events import build_incident_event
from agent_core.incident import IncidentAggregate
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from remediation.evaluations.evidence_evaluator import run_evidence_evaluation
from remediation.evidence import IncidentEvidenceReporter, generate_report
from remediation.evidence_demos import _NOW, _sample_events, run_all_evidence_demos
from remediation.reporting import (
    ArtifactIntegrityStatus,
    EvidenceReportContext,
    build_phase12_traceability_matrix,
    export_report_bundle,
    redact_structured_data,
    verify_artifact_integrity,
    verify_report_bundle,
)
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceCompleteness,
    EvidenceProvenance,
    IncidentState,
)
from shared.identifiers import generate_correlation_id
from shared.schemas import ArtifactReference
from shared.serialization import sha256_bytes


def test_redaction_preserves_original_bytes_and_redacts_nested_secrets() -> None:
    raw = {
        "db_url": "postgresql://user:s3cr3tpass@localhost/db",
        "api_key": "sk-abcdef1234567890abcd",
    }
    sanitized, summary = redact_structured_data(raw)
    assert summary["redaction_applied"] is True
    assert "s3cr3tpass" not in json.dumps(sanitized)
    assert "abcdef1234567890" not in json.dumps(sanitized)
    # Original dict untouched
    assert raw["api_key"] == "sk-abcdef1234567890abcd"


def test_artifact_integrity_verification_classifications() -> None:
    content = b'{"hello": "world"}'
    ref = ArtifactReference(
        artifact_id="art_int_01",
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        incident_id="inc_int",
        content_hash=sha256_bytes(content),
        size_bytes=len(content),
        storage_ref="mem://art_int_01",
        producer="sec_verifier",
        content_type="application/json",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    assert (
        verify_artifact_integrity(ref, content, expected_incident_id="inc_int").status
        == ArtifactIntegrityStatus.VERIFIED
    )
    assert (
        verify_artifact_integrity(ref, None, expected_incident_id="inc_int").status
        == ArtifactIntegrityStatus.METADATA_ONLY
    )
    assert (
        verify_artifact_integrity(
            ref, b'{"hello": "TAMPR"}', expected_incident_id="inc_int"
        ).status
        == ArtifactIntegrityStatus.HASH_MISMATCH
    )
    assert (
        verify_artifact_integrity(ref, content, expected_incident_id="inc_other").status
        == ArtifactIntegrityStatus.INCIDENT_MISMATCH
    )


def test_bundle_export_and_tamper_detection() -> None:
    reporter = IncidentEvidenceReporter()
    events = _sample_events("inc_bndl")
    ctx = EvidenceReportContext(
        incident_id="inc_bndl",
        incident_status=IncidentState.RECEIVED,
        accepted_events=events,
        generation_timestamp=_NOW,
        fixture_mode=True,
    )
    rep, miss = reporter.build_report_with_details(ctx)
    md = reporter.render_markdown(rep, context=ctx, missing_items=miss)
    js = reporter.render_json(rep, context=ctx, missing_items=miss)
    with tempfile.TemporaryDirectory() as tmp:
        bdir, manifest = export_report_bundle(
            base_dir=Path(tmp), report=rep, markdown_content=md, json_payload=js
        )
        assert manifest.incident_id == "inc_bndl"
        assert verify_report_bundle(bdir).valid is True
        # Tamper
        (bdir / "report.md").write_text("tampered", encoding="utf-8")
        res = verify_report_bundle(bdir)
        assert res.valid is False
        assert len(res.failures) >= 1


@pytest.mark.asyncio
async def test_orchestrator_execute_evidence_reporting_non_mutating() -> None:
    repo = InMemoryOrchestrationRepository()
    inc_id = "inc_orch_11"
    corr_id = generate_correlation_id()
    ev1 = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.FINDING_RECEIVED,
        actor="scanner",
        actor_type=ActorType.SECURITY_SCANNER,
        sequence_number=1,
        correlation_id=corr_id,
        timestamp_utc=_NOW - timedelta(minutes=5),
        payload={
            "finding_id": "fnd_11",
            "category": "sql_injection",
            "severity": "critical",
            "status": "suspected",
        },
    )
    agg = IncidentAggregate(
        incident_id=inc_id,
        finding_id="fnd_11",
        environment="demo-staging",
        current_state=IncidentState.CONTAINED,
        incident_version=1,
        correlation_id=corr_id,
        latest_event_id=ev1.event_id,
        latest_event_sequence=1,
        created_at=_NOW - timedelta(minutes=5),
        updated_at=_NOW - timedelta(minutes=5),
        is_synthetic_fixture=True,
    )
    await repo.create_incident(
        agg,
        initial_event=ev1,
        initial_result=EventProcessingResult(
            accepted=True,
            incident_id=inc_id,
            event_id=ev1.event_id,
            previous_state=IncidentState.RECEIVED,
            current_state=IncidentState.CONTAINED,
            incident_version=1,
            reason_code="CONTAINMENT_VERIFIED",
        ),
    )
    raw = b'{"contained": true}'
    await repo.store_artifact(
        ArtifactReference(
            artifact_id="art_orch_11",
            artifact_type=ArtifactType.REGRESSION_LOG,
            incident_id=inc_id,
            content_hash=sha256_bytes(raw),
            size_bytes=len(raw),
            storage_ref="mem://art_orch_11",
            producer="sec_verifier",
            content_type="application/json",
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        ),
        content=raw,
    )
    orch = IncidentOrchestrator(repository=repo, evidence_repository=repo, fixture_mode=True)
    report, md, js, ev_res = await orch.execute_evidence_reporting(incident_id=inc_id)
    assert ev_res.accepted is True
    assert ev_res.current_state == IncidentState.CONTAINED  # Does not mutate operational state
    assert report.completeness in (
        EvidenceCompleteness.INCOMPLETE,
        EvidenceCompleteness.PARTIAL,
        EvidenceCompleteness.COMPLETE,
    )
    assert "Killswitch X" in md
    assert js["incident_id"] == inc_id


def test_evidence_demos_evaluator_and_traceability_matrix() -> None:
    demos = run_all_evidence_demos()
    assert demos["demo_g_redaction"]["contains_secret_in_json"] is False
    assert demos["demo_g_redaction"]["contains_secret_in_md"] is False
    assert demos["demo_h_i_reproducibility_and_tampering"]["deterministic_md"] is True
    assert demos["demo_h_i_reproducibility_and_tampering"]["tampered_bundle_detected"] is True

    md, js = generate_report(_sample_events("inc_rm"), {"fixture_mode": True})
    assert "Killswitch X" in md and js["incident_id"] == "inc_rm"

    matrix = build_phase12_traceability_matrix()
    assert any(r["phase"] == "06" and r["status"] == "not_implemented" for r in matrix)
    assert any(r["phase"] == "11" and r["status"] == "implemented_verified" for r in matrix)

    report = run_evidence_evaluation(write_reports=False)
    assert report["passed_cases"] == report["total_cases"]
    assert report["unsupported_verified_claims"] == 0
    assert report["false_deployment_claims"] == 0
    assert report["false_recovery_claims"] == 0
    assert report["undetected_artifact_corruption"] == 0
    assert report["unredacted_secrets"] == 0
