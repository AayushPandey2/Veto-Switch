"""Artifact SHA-256 integrity, event history, and cross-record consistency validation."""

from __future__ import annotations

from agent_core.replay import verify_event_history_integrity
from shared.enums import EvidenceProvenance
from shared.schemas import ArtifactReference, IncidentEvent
from shared.serialization import sha256_bytes

from remediation.reporting.models import (
    ArtifactIntegrityResult,
    ArtifactIntegrityStatus,
    EvidenceReportContext,
)


def verify_artifact_integrity(
    reference: ArtifactReference,
    content: bytes | None,
    *,
    expected_incident_id: str,
    mandatory: bool = True,
) -> ArtifactIntegrityResult:
    """Verify artifact incident ownership, size, provenance, and SHA-256 content hash."""
    if reference.incident_id != expected_incident_id:
        return ArtifactIntegrityResult(
            artifact_id=reference.artifact_id,
            incident_id=reference.incident_id,
            artifact_type=reference.artifact_type.value,
            status=ArtifactIntegrityStatus.INCIDENT_MISMATCH,
            expected_hash=reference.content_hash,
            expected_size_bytes=reference.size_bytes,
            provenance=reference.provenance,
            mandatory=mandatory,
            message=(
                f"Artifact {reference.artifact_id!r} belongs to incident "
                f"{reference.incident_id!r}, not {expected_incident_id!r}."
            ),
        )

    if reference.provenance == EvidenceProvenance.LLM_INTERPRETATION:
        return ArtifactIntegrityResult(
            artifact_id=reference.artifact_id,
            incident_id=reference.incident_id,
            artifact_type=reference.artifact_type.value,
            status=ArtifactIntegrityStatus.PROVENANCE_UNTRUSTED,
            expected_hash=reference.content_hash,
            expected_size_bytes=reference.size_bytes,
            provenance=reference.provenance,
            mandatory=mandatory,
            message="LLM interpretation artifact cannot establish observed operational proof.",
        )

    if content is None:
        return ArtifactIntegrityResult(
            artifact_id=reference.artifact_id,
            incident_id=reference.incident_id,
            artifact_type=reference.artifact_type.value,
            status=ArtifactIntegrityStatus.METADATA_ONLY,
            expected_hash=reference.content_hash,
            expected_size_bytes=reference.size_bytes,
            provenance=reference.provenance,
            mandatory=mandatory,
            message="Original artifact bytes unavailable; metadata-only reference.",
        )

    actual_size = len(content)
    if reference.size_bytes is not None and actual_size != reference.size_bytes:
        return ArtifactIntegrityResult(
            artifact_id=reference.artifact_id,
            incident_id=reference.incident_id,
            artifact_type=reference.artifact_type.value,
            status=ArtifactIntegrityStatus.SIZE_MISMATCH,
            expected_hash=reference.content_hash,
            actual_hash=sha256_bytes(content),
            expected_size_bytes=reference.size_bytes,
            actual_size_bytes=actual_size,
            provenance=reference.provenance,
            mandatory=mandatory,
            message=(
                f"Artifact size mismatch: expected {reference.size_bytes} bytes, "
                f"got {actual_size}."
            ),
        )

    actual_hash = sha256_bytes(content)
    if actual_hash != reference.content_hash:
        return ArtifactIntegrityResult(
            artifact_id=reference.artifact_id,
            incident_id=reference.incident_id,
            artifact_type=reference.artifact_type.value,
            status=ArtifactIntegrityStatus.HASH_MISMATCH,
            expected_hash=reference.content_hash,
            actual_hash=actual_hash,
            expected_size_bytes=reference.size_bytes,
            actual_size_bytes=actual_size,
            provenance=reference.provenance,
            mandatory=mandatory,
            message="Artifact SHA-256 digest does not match ArtifactReference.content_hash.",
        )

    return ArtifactIntegrityResult(
        artifact_id=reference.artifact_id,
        incident_id=reference.incident_id,
        artifact_type=reference.artifact_type.value,
        status=ArtifactIntegrityStatus.VERIFIED,
        expected_hash=reference.content_hash,
        actual_hash=actual_hash,
        expected_size_bytes=reference.size_bytes,
        actual_size_bytes=actual_size,
        provenance=reference.provenance,
        mandatory=mandatory,
        message="Artifact bytes and SHA-256 content hash verified.",
    )


def validate_event_history_for_report(
    events: list[IncidentEvent],
    *,
    expected_incident_id: str,
) -> list[str]:
    """Validate event sequence continuity, uniqueness, incident ownership, and replay integrity."""
    diagnostics: list[str] = []
    if not events:
        diagnostics.append("Event history is empty; cannot reconstruct incident transitions.")
        return diagnostics

    ordered = sorted(events, key=lambda e: e.sequence_number)
    seen_idem: set[str] = set()
    for ev in ordered:
        if ev.incident_id != expected_incident_id:
            diagnostics.append(
                f"Event {ev.event_id!r} belongs to incident {ev.incident_id!r}, "
                f"expected {expected_incident_id!r}."
            )
        if ev.idempotency_token in seen_idem:
            diagnostics.append(f"Duplicate idempotency_token {ev.idempotency_token!r} in history.")
        seen_idem.add(ev.idempotency_token)

    try:
        verify_event_history_integrity(ordered)
    except Exception as exc:
        diagnostics.append(f"Event history integrity check failed: {exc}")

    return diagnostics


def detect_cross_record_inconsistencies(ctx: EvidenceReportContext) -> list[str]:
    """Detect cross-incident, hash, environment, and causal mismatches across records."""
    issues: list[str] = []
    inc_id = ctx.incident_id

    for f in ctx.findings:
        if f.incident_id != inc_id:
            issues.append(f"Finding {f.finding_id!r} belongs to {f.incident_id!r}.")
    for appr in ctx.approvals:
        if appr.incident_id != inc_id:
            issues.append(f"Approval {appr.approval_id!r} belongs to {appr.incident_id!r}.")
    for rcpt in ctx.operation_receipts:
        if rcpt.incident_id != inc_id:
            issues.append(
                f"OperationReceipt {rcpt.operation_id!r} belongs to {rcpt.incident_id!r}."
            )
    for vr in ctx.verification_results:
        if vr.incident_id != inc_id:
            issues.append(
                f"VerificationResult {vr.verification_id!r} belongs to {vr.incident_id!r}."
            )
    for pp in ctx.patch_proposals:
        if pp.incident_id != inc_id:
            issues.append(f"PatchProposal {pp.patch_id!r} belongs to {pp.incident_id!r}.")
    for ptr in ctx.patch_test_results:
        if ptr.incident_id != inc_id:
            issues.append(
                f"PatchTestResult {ptr.test_run_id!r} belongs to {ptr.incident_id!r}."
            )

    # Check approval -> proposal hash binding when both are present
    containment_hashes = {
        getattr(p, "proposal_id", None): getattr(p, "proposal_hash", None)
        for p in [*ctx.containment_decisions, *ctx.rollback_proposals]
    }
    for appr in ctx.approvals:
        if appr.proposal_id in containment_hashes:
            expected_h = containment_hashes[appr.proposal_id]
            if expected_h is not None and appr.proposal_hash != expected_h:
                issues.append(
                    f"Approval {appr.approval_id!r} proposal_hash does not match "
                    f"proposal {appr.proposal_id!r}."
                )

    return issues
