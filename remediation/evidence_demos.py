"""Offline reproducible demonstrations for Phase 11 Incident Evidence Intelligence."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_core.events import build_incident_event
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FindingStatus,
    IncidentState,
    OperationOutcome,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    FeatureState,
    Finding,
    OperationReceipt,
    VerificationResult,
)
from shared.serialization import sha256_bytes, sha256_text

from remediation.evidence import IncidentEvidenceReporter, generate_report
from remediation.reporting import (
    EvidenceReportContext,
    export_report_bundle,
    serialize_evidence_dashboard,
    verify_report_bundle,
)

_NOW = datetime(2026, 11, 28, 4, 0, 0, tzinfo=UTC)


def _sample_events(inc_id: str) -> list[Any]:
    return [
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.FINDING_RECEIVED,
            actor="scanner",
            actor_type=ActorType.SECURITY_SCANNER,
            sequence_number=1,
            correlation_id="corr_11_demo",
            timestamp_utc=_NOW - timedelta(minutes=10),
            payload={
                "finding_id": "fnd_11_01",
                "category": "sql_injection",
                "severity": "critical",
                "status": "suspected",
            },
        ),
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.VULNERABILITY_REPRODUCED,
            actor="sec_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=2,
            correlation_id="corr_11_demo",
            timestamp_utc=_NOW - timedelta(minutes=8),
            payload={
                "verification_id": "ver_11_before",
                "reproduced": True,
                "tested_revision": "rev_001",
            },
        ),
        build_incident_event(
            incident_id=inc_id,
            event_type=EventType.CONTAINMENT_CONFIRMED,
            actor="sec_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id="corr_11_demo",
            timestamp_utc=_NOW - timedelta(minutes=5),
            payload={
                "verification_id": "ver_11_after",
                "passed": True,
                "tested_revision": "rev_001",
            },
        ),
    ]


def run_all_evidence_demos() -> dict[str, Any]:
    """Run Phase 11 Demos A-I offline."""
    reporter = IncidentEvidenceReporter()
    inc_id = "inc_demo_11"
    events = _sample_events(inc_id)
    art_bytes = b'{"status": "reproduced", "token": "Bearer supersecret_tok_123456"}'
    art_ref = ArtifactReference(
        artifact_id="art_demo_11_01",
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        incident_id=inc_id,
        content_hash=sha256_bytes(art_bytes),
        size_bytes=len(art_bytes),
        storage_ref="mem://art_demo_11_01",
        producer="sec_verifier",
        content_type="application/json",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    finding = Finding(
        finding_id="fnd_11_01",
        incident_id=inc_id,
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        status=FindingStatus.REPRODUCED,
        affected_route="/search",
        affected_component="search_service",
        environment="demo-staging",
        repository_revision="rev_001",
        source_scanner="semgrep",
        observed_impact="Boolean-based SQL injection reproduced on /search.",
        evidence_ids=["art_demo_11_01"],
    )
    appr = ApprovalDecision(
        approval_id="appr_11_01",
        proposal_id="prop_11_01",
        proposal_hash=sha256_text("prop_11_01"),
        incident_id=inc_id,
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_11",
        decided_at=_NOW - timedelta(minutes=6),
        expires_at=_NOW + timedelta(minutes=10),
        authorization_context_ref="auth_11",
    )
    rcpt = OperationReceipt(
        operation_id="op_11_01",
        incident_id=inc_id,
        proposal_id="prop_11_01",
        approval_id="appr_11_01",
        environment="demo-staging",
        target_feature="search_v1",
        requested_state=False,
        observed_state=False,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key="idem_11_01",
        executed_at=_NOW - timedelta(minutes=5),
        evidence_ids=["art_demo_11_01"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    fs = FeatureState(
        feature_id="feat_search_v1",
        environment="demo-staging",
        feature_name="search_v1",
        enabled=False,
        observed_at=_NOW - timedelta(minutes=5),
    )
    ver_before = VerificationResult(
        verification_id="ver_11_before",
        incident_id=inc_id,
        test_id="test_sqli",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        tested_revision="rev_001",
        artifact_ids=["art_demo_11_01"],
        completed_at=_NOW - timedelta(minutes=8),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    ver_after = VerificationResult(
        verification_id="ver_11_after",
        incident_id=inc_id,
        test_id="test_sqli",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision="rev_001",
        artifact_ids=["art_demo_11_01"],
        completed_at=_NOW - timedelta(minutes=5),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )

    outputs: dict[str, Any] = {}

    # Demo A/B — Containment verified
    ctx_a = EvidenceReportContext(
        incident_id=inc_id,
        environment="demo-staging",
        incident_status=IncidentState.CONTAINED,
        accepted_events=events,
        findings=[finding],
        approvals=[appr],
        operation_receipts=[rcpt],
        feature_state_observations=[fs],
        verification_results=[ver_before, ver_after],
        artifact_references=[art_ref],
        artifact_contents={art_ref.artifact_id: art_bytes},
        generation_timestamp=_NOW,
        fixture_mode=True,
    )
    rep_a, miss_a = reporter.build_report_with_details(ctx_a)
    outputs["demo_a_containment_report"] = serialize_evidence_dashboard(rep_a)

    # Demo E — Missing evidence (RECOVERED without DeploymentEvidence)
    ctx_e = ctx_a.model_copy(update={"incident_status": IncidentState.RECOVERED})
    rep_e, miss_e = reporter.build_report_with_details(ctx_e)
    outputs["demo_e_missing_deployment"] = {
        "completeness": rep_e.completeness.value,
        "missing_count": len(miss_e),
    }

    # Demo F — Corrupted artifact
    ctx_f = ctx_a.model_copy(update={"artifact_contents": {art_ref.artifact_id: b"tampered_bytes"}})
    rep_f, _ = reporter.build_report_with_details(ctx_f)
    outputs["demo_f_corrupted_artifact"] = {
        "completeness": rep_f.completeness.value,
        "integrity_statuses": [a["status"] for a in rep_f.artifact_integrity_results],
    }

    # Demo G — Secret redaction
    md_g, js_g = generate_report(
        events,
        {
            "incident_status": IncidentState.CONTAINED.value,
            "artifact_references": [art_ref],
            "artifact_contents": {art_ref.artifact_id: art_bytes},
            "fixture_mode": True,
        },
    )
    outputs["demo_g_redaction"] = {
        "contains_secret_in_json": "supersecret" in json.dumps(js_g),
        "contains_secret_in_md": "supersecret" in md_g,
    }

    # Demo H & I — Deterministic regeneration + Bundle tampering detection
    md_1 = reporter.render_markdown(rep_a, context=ctx_a, missing_items=miss_a)
    js_1 = reporter.render_json(rep_a, context=ctx_a, missing_items=miss_a)
    md_2 = reporter.render_markdown(rep_a, context=ctx_a, missing_items=miss_a)
    js_2 = reporter.render_json(rep_a, context=ctx_a, missing_items=miss_a)
    with tempfile.TemporaryDirectory() as tmp:
        bdir, _ = export_report_bundle(
            base_dir=Path(tmp), report=rep_a, markdown_content=md_1, json_payload=js_1
        )
        ok_ver = verify_report_bundle(bdir)
        (bdir / "report.md").write_text("TAMPERED", encoding="utf-8")
        bad_ver = verify_report_bundle(bdir)
        outputs["demo_h_i_reproducibility_and_tampering"] = {
            "deterministic_md": md_1 == md_2,
            "deterministic_json": js_1 == js_2,
            "valid_bundle": ok_ver.valid,
            "tampered_bundle_detected": not bad_ver.valid,
        }

    return outputs


if __name__ == "__main__":
    print(json.dumps(run_all_evidence_demos(), indent=2, default=str))
