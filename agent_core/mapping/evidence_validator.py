"""Evidence existence, provenance, and revision validation for flag mapping."""

from __future__ import annotations

from shared.contracts import EvidenceRepository
from shared.enums import EvidenceProvenance, FindingStatus, MappingReasonCode
from shared.serialization import sha256_bytes

from agent_core.mapping.models import EvidenceValidationOutcome, MappingContext

_LIVE_REJECTED_PROVENANCE: frozenset[EvidenceProvenance] = frozenset(
    {
        EvidenceProvenance.REFERENCE_FIXTURE,
        EvidenceProvenance.SYNTHETIC_TELEMETRY,
        EvidenceProvenance.LLM_INTERPRETATION,
    }
)


async def validate_mapping_evidence(
    context: MappingContext,
    *,
    evidence_repo: EvidenceRepository | None = None,
    content_by_id: dict[str, bytes] | None = None,
) -> EvidenceValidationOutcome:
    """Validate finding status, reproduction evidence, provenance, and revisions."""
    finding = context.finding
    reason_codes: list[MappingReasonCode] = []
    limitations: list[str] = []
    missing_evidence: list[str] = []
    verified_ids: list[str] = []

    is_suspected = finding.status == FindingStatus.SUSPECTED
    if is_suspected:
        reason_codes.append(MappingReasonCode.UNVERIFIED_FINDING)
        limitations.append(
            "Finding status is 'suspected'; reproduction verification is required before "
            "operational containment."
        )

    is_fixture_only = context.fixture_mode or finding.provenance in _LIVE_REJECTED_PROVENANCE
    if not context.fixture_mode and finding.provenance in _LIVE_REJECTED_PROVENANCE:
        reason_codes.append(MappingReasonCode.FIXTURE_ONLY_EVIDENCE)
        limitations.append(
            f"Finding provenance {finding.provenance.value!r} cannot authorize live operational "
            "progression."
        )

    if not finding.evidence_ids:
        reason_codes.append(MappingReasonCode.INSUFFICIENT_EVIDENCE)
        missing_evidence.append("reproduction_evidence_id")
        limitations.append("Finding carries no evidence_ids.")

    artifacts_by_id = {a.artifact_id: a for a in context.artifact_references}
    expected_rev = context.application_revision or finding.repository_revision

    for eid in finding.evidence_ids:
        art = artifacts_by_id.get(eid)
        if art is not None:
            if art.incident_id != finding.incident_id:
                reason_codes.append(MappingReasonCode.EVIDENCE_INCIDENT_MISMATCH)
                limitations.append(
                    f"Artifact {eid!r} belongs to incident {art.incident_id!r}, "
                    f"not {finding.incident_id!r}."
                )
                continue
            if (
                expected_rev
                and art.source_revision
                and art.source_revision != expected_rev
            ):
                reason_codes.append(MappingReasonCode.EVIDENCE_REVISION_MISMATCH)
                limitations.append(
                    f"Artifact {eid!r} revision {art.source_revision!r} != {expected_rev!r}."
                )
                continue
            if not context.fixture_mode and art.provenance in _LIVE_REJECTED_PROVENANCE:
                reason_codes.append(MappingReasonCode.FIXTURE_ONLY_EVIDENCE)
                limitations.append(
                    f"Artifact {eid!r} has non-live provenance {art.provenance.value!r}."
                )
                continue

        if not context.fixture_mode:
            if evidence_repo is None:
                if art is None:
                    reason_codes.append(MappingReasonCode.EVIDENCE_NOT_FOUND)
                    missing_evidence.append(eid)
                    limitations.append(
                        f"Evidence {eid!r} cannot be verified without EvidenceRepository "
                        "in live mode."
                    )
                    continue
            else:
                exists = await evidence_repo.artifact_exists(eid, incident_id=finding.incident_id)
                if not exists:
                    reason_codes.append(MappingReasonCode.EVIDENCE_NOT_FOUND)
                    missing_evidence.append(eid)
                    limitations.append(
                        f"Evidence {eid!r} not found or bound to another incident."
                    )
                    continue
                stored_ref = await evidence_repo.get_artifact_reference(eid)
                if (
                    stored_ref is not None
                    and content_by_id
                    and eid in content_by_id
                    and sha256_bytes(content_by_id[eid]) != stored_ref.content_hash
                ):
                    reason_codes.append(MappingReasonCode.INSUFFICIENT_EVIDENCE)
                    limitations.append(f"Artifact {eid!r} SHA-256 content mismatch.")
                    continue
        verified_ids.append(eid)

    blocking_codes = {
        MappingReasonCode.UNVERIFIED_FINDING,
        MappingReasonCode.INSUFFICIENT_EVIDENCE,
        MappingReasonCode.EVIDENCE_NOT_FOUND,
        MappingReasonCode.EVIDENCE_INCIDENT_MISMATCH,
        MappingReasonCode.EVIDENCE_REVISION_MISMATCH,
    }
    if not context.fixture_mode:
        blocking_codes.add(MappingReasonCode.FIXTURE_ONLY_EVIDENCE)

    actionable = (
        not is_suspected
        and len(verified_ids) > 0
        and not any(c in blocking_codes for c in reason_codes)
    )

    return EvidenceValidationOutcome(
        actionable=actionable,
        reproduced=not is_suspected,
        is_suspected=is_suspected,
        is_fixture_only=is_fixture_only,
        verified_evidence_ids=verified_ids,
        missing_evidence=sorted(set(missing_evidence)),
        reason_codes=sorted(set(reason_codes), key=lambda c: c.value),
        limitations=limitations,
    )
