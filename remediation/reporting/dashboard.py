"""Dashboard summary serializer and Phase 12 requirements traceability matrix."""

from __future__ import annotations

from typing import Any

from shared.schemas import EvidenceReport

from remediation.reporting.models import ArtifactIntegrityStatus


def serialize_evidence_dashboard(
    report: EvidenceReport,
    *,
    export_references: list[str] | None = None,
) -> dict[str, Any]:
    """Produce a stable dashboard summary consistent with the canonical EvidenceReport."""
    verified_claims = sum(
        1 for c in report.claim_evidence_links if c.get("verification_status") == "verified"
    )
    unverified_claims = len(report.claim_evidence_links) - verified_claims
    verified_arts = sum(
        1
        for a in report.artifact_integrity_results
        if a.get("status") == ArtifactIntegrityStatus.VERIFIED.value
    )
    missing_arts = sum(
        1
        for a in report.artifact_integrity_results
        if a.get("status")
        in (
            ArtifactIntegrityStatus.MISSING.value,
            ArtifactIntegrityStatus.METADATA_ONLY.value,
            ArtifactIntegrityStatus.CONTENT_UNAVAILABLE.value,
        )
    )
    corrupted_arts = sum(
        1
        for a in report.artifact_integrity_results
        if a.get("status")
        in (
            ArtifactIntegrityStatus.HASH_MISMATCH.value,
            ArtifactIntegrityStatus.SIZE_MISMATCH.value,
            ArtifactIntegrityStatus.INCIDENT_MISMATCH.value,
        )
    )
    return {
        "incident_id": report.incident_id,
        "report_id": report.report_id,
        "incident_status": report.incident_status.value,
        "snapshot_sequence": report.snapshot_sequence or len(report.timeline),
        "evidence_completeness": report.completeness.value,
        "verified_claim_count": verified_claims,
        "unverified_claim_count": unverified_claims,
        "required_artifact_count": len(report.artifact_references),
        "verified_artifact_count": verified_arts,
        "missing_artifact_count": missing_arts,
        "corrupted_artifact_count": corrupted_arts,
        "limitations_count": len(report.limitations),
        "report_export_references": list(export_references or []),
    }


def build_phase12_traceability_matrix() -> list[dict[str, str]]:
    """Consolidated Phase 01-12 requirements traceability matrix for Phase 12 handoff."""
    return [
        {
            "requirement_id": "REQ-01-FOUNDATION",
            "phase": "01",
            "implementation_location": "shared/, config/, scripts/validate_fixtures.py",
            "status": "implemented_verified",
            "remaining_work": "None",
        },
        {
            "requirement_id": "REQ-02-ORCHESTRATION",
            "phase": "02",
            "implementation_location": "agent_core/orchestrator.py, state_machine.py, guards.py",
            "status": "implemented_verified",
            "remaining_work": (
                "Replace InMemoryOrchestrationRepository with durable DB in feat/platform"
            ),
        },
        {
            "requirement_id": "REQ-03-INVESTIGATOR",
            "phase": "03",
            "implementation_location": "agent_core/investigator.py, agent_core/llm/",
            "status": "implemented_verified",
            "remaining_work": "None for offline/Gemini REST",
        },
        {
            "requirement_id": "REQ-04-FLAG-MAPPING",
            "phase": "04",
            "implementation_location": "agent_core/flag_mapper.py, agent_core/mapping/",
            "status": "implemented_verified",
            "remaining_work": "None",
        },
        {
            "requirement_id": "REQ-05-BLAST-RADIUS-CONTAINMENT",
            "phase": "05",
            "implementation_location": "agent_core/blast_radius.py, containment_strategist.py",
            "status": "implemented_verified",
            "remaining_work": "Live Flagsmith execution owned by feat/platform",
        },
        {
            "requirement_id": "REQ-06-COVERAGE-AUDITOR",
            "phase": "06",
            "implementation_location": "agent_core/flag_auditor.py (missing)",
            "status": "not_implemented",
            "remaining_work": (
                "No Prompt 06 specification present; requires AST route coverage auditor"
            ),
        },
        {
            "requirement_id": "REQ-07-PATCH-ENGINEER",
            "phase": "07",
            "implementation_location": "remediation/patch_agent.py, remediation/patching/",
            "status": "implemented_verified",
            "remaining_work": "Cross-branch platform_demo_app target registration",
        },
        {
            "requirement_id": "REQ-08-PATCH-VERIFICATION",
            "phase": "08",
            "implementation_location": "remediation/patch_tests.py, remediation/verification/",
            "status": "implemented_verified",
            "remaining_work": "Live isolated security runner in feat/security",
        },
        {
            "requirement_id": "REQ-09-PROGRESSIVE-ROLLOUT",
            "phase": "09",
            "implementation_location": (
                "remediation/rollout_agent.py, remediation/release/, policies.py"
            ),
            "status": "implemented_verified",
            "remaining_work": "Live Flagsmith percentage targeting & telemetry integration",
        },
        {
            "requirement_id": "REQ-10-ROLLBACK-INTELLIGENCE",
            "phase": "10",
            "implementation_location": "remediation/rollback.py, remediation/recovery/",
            "status": "implemented_verified",
            "remaining_work": (
                "Live Flagsmith targeting rollback & post-rollback verification"
            ),
        },
        {
            "requirement_id": "REQ-11-EVIDENCE-REPORTING",
            "phase": "11",
            "implementation_location": "remediation/evidence.py, remediation/reporting/",
            "status": "implemented_verified",
            "remaining_work": "Optional PDF/HTML export & durable artifact storage",
        },
        {
            "requirement_id": "REQ-12-FINAL-E2E-INTEGRATION",
            "phase": "12",
            "implementation_location": "Not present",
            "status": "not_implemented",
            "remaining_work": (
                "No Prompt 12 specification present; cross-branch E2E stabilization pending"
            ),
        },
    ]
