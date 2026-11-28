"""Evidence existence, provenance, integrity, and trust-boundary validation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from shared.contracts import EvidenceRepository
from shared.enums import ActorType, ArtifactType, EvidenceProvenance
from shared.identifiers import ensure_utc
from shared.schemas import ArtifactReference, IncidentEvent
from shared.serialization import sha256_bytes

from agent_core.context import Clock, GuardResult, ProducerContext, SystemClock, TransitionContext
from agent_core.incident import IncidentAggregate

_LIVE_REJECTED_PROVENANCE: frozenset[EvidenceProvenance] = frozenset(
    {
        EvidenceProvenance.REFERENCE_FIXTURE,
        EvidenceProvenance.SYNTHETIC_TELEMETRY,
        EvidenceProvenance.LLM_INTERPRETATION,
    }
)


class EvidenceValidator:
    """Validates evidence artifacts against an ``EvidenceRepository`` and trust rules."""

    def __init__(
        self,
        evidence_repository: EvidenceRepository | None = None,
        *,
        clock: Clock | None = None,
        fixture_mode: bool = False,
    ) -> None:
        self._repo = evidence_repository
        self._clock: Clock = clock or SystemClock()
        self._fixture_mode = fixture_mode

    async def verify_artifact_ids_exist(
        self,
        *,
        incident_id: str,
        evidence_ids: Sequence[str],
        content_by_id: dict[str, bytes] | None = None,
    ) -> GuardResult:
        """Asynchronously verify referenced evidence IDs in the EvidenceRepository."""
        if not evidence_ids:
            return GuardResult(
                allowed=False,
                guard="evidence_existence",
                reason_code="MISSING_EVIDENCE_REFERENCES",
                message="At least one evidence reference is required.",
                missing_requirements=["evidence_ids"],
                evidence_ids=[],
                retryable=False,
            )

        if self._repo is None:
            return GuardResult(
                allowed=False,
                guard="evidence_existence",
                reason_code="EVIDENCE_REPOSITORY_UNAVAILABLE",
                message="Evidence repository is not configured; failing closed.",
                missing_requirements=["evidence_repository"],
                evidence_ids=list(evidence_ids),
                retryable=True,
            )

        missing: list[str] = []
        hash_mismatches: list[str] = []
        for art_id in evidence_ids:
            exists = await self._repo.artifact_exists(art_id, incident_id=incident_id)
            if not exists:
                missing.append(art_id)
                continue
            ref = await self._repo.get_artifact_reference(art_id)
            if (
                ref is not None
                and content_by_id
                and art_id in content_by_id
                and sha256_bytes(content_by_id[art_id]) != ref.content_hash
            ):
                hash_mismatches.append(art_id)

        if missing:
            return GuardResult(
                allowed=False,
                guard="evidence_existence",
                reason_code="EVIDENCE_NOT_FOUND",
                message=f"Referenced evidence missing or bound to another incident: {missing}",
                missing_requirements=missing,
                evidence_ids=list(evidence_ids),
                retryable=False,
            )
        if hash_mismatches:
            return GuardResult(
                allowed=False,
                guard="evidence_existence",
                reason_code="ARTIFACT_HASH_MISMATCH",
                message=f"Artifact SHA-256 content mismatch detected for: {hash_mismatches}",
                missing_requirements=hash_mismatches,
                evidence_ids=list(evidence_ids),
                retryable=False,
            )
        return GuardResult(
            allowed=True,
            guard="evidence_existence",
            reason_code="EVIDENCE_VERIFIED",
            message="All referenced evidence artifacts exist and match incident identity.",
            evidence_ids=list(evidence_ids),
        )


def validate_producer_for_evidence(
    producer: ProducerContext,
    *,
    allowed_actor_types: frozenset[ActorType],
) -> GuardResult:
    """Ensure evidence claims come from an authenticated trusted producer channel."""
    if not producer.authenticated:
        return GuardResult(
            allowed=False,
            guard="producer_authenticity",
            reason_code="UNAUTHENTICATED_PRODUCER",
            message=(
                f"Producer {producer.producer_id!r} on channel {producer.trusted_channel!r} "
                "is not authenticated."
            ),
            missing_requirements=["authenticated_producer_context"],
            retryable=False,
        )
    if producer.actor_type not in allowed_actor_types:
        return GuardResult(
            allowed=False,
            guard="producer_authenticity",
            reason_code="UNAUTHORIZED_PRODUCER_TYPE",
            message=(
                f"Actor type {producer.actor_type.value!r} is not authorized for this action."
            ),
            missing_requirements=["authorized_actor_type"],
            retryable=False,
        )
    return GuardResult(
        allowed=True,
        guard="producer_authenticity",
        reason_code="PRODUCER_AUTHENTICATED",
        message="Producer identity verified via trusted channel.",
    )


def validate_provenance_for_mode(
    provenance: EvidenceProvenance,
    *,
    fixture_mode: bool,
    producer_mode: str,
    require_observed_in_live: bool = True,
) -> GuardResult:
    """Enforce strict separation between live operational evidence and synthetic fixtures."""
    if not fixture_mode and producer_mode == "fixture":
        return GuardResult(
            allowed=False,
            guard="evidence_provenance",
            reason_code="FIXTURE_EVIDENCE_IN_LIVE_MODE",
            message="Fixture producer context is prohibited in live operational mode.",
            missing_requirements=["live_observed_evidence"],
            retryable=False,
        )
    if not fixture_mode and require_observed_in_live and provenance in _LIVE_REJECTED_PROVENANCE:
        return GuardResult(
            allowed=False,
            guard="evidence_provenance",
            reason_code="UNTRUSTED_PROVENANCE_IN_LIVE_MODE",
            message=(
                f"Provenance {provenance.value!r} cannot satisfy live operational "
                "verification requirements."
            ),
            missing_requirements=["observed_operational_evidence"],
            retryable=False,
        )
    return GuardResult(
        allowed=True,
        guard="evidence_provenance",
        reason_code="PROVENANCE_ACCEPTED",
        message=f"Evidence provenance {provenance.value!r} accepted for current mode.",
    )


def validate_artifact_metadata(
    artifact: ArtifactReference,
    *,
    incident: IncidentAggregate,
    expected_type: ArtifactType | None = None,
    expected_revision: str | None = None,
    reference_time: datetime | None = None,
) -> GuardResult:
    """Validate artifact incident ownership, type, revision, and timestamp sanity."""
    if artifact.incident_id != incident.incident_id:
        return GuardResult(
            allowed=False,
            guard="evidence_existence",
            reason_code="EVIDENCE_INCIDENT_MISMATCH",
            message="Artifact belongs to a different incident.",
            missing_requirements=["matching_incident_artifact"],
            evidence_ids=[artifact.artifact_id],
        )
    if expected_type is not None and artifact.artifact_type != expected_type:
        return GuardResult(
            allowed=False,
            guard="evidence_existence",
            reason_code="EVIDENCE_TYPE_MISMATCH",
            message=(
                f"Expected artifact_type {expected_type.value!r}, "
                f"got {artifact.artifact_type.value!r}."
            ),
            missing_requirements=[expected_type.value],
            evidence_ids=[artifact.artifact_id],
        )
    if (
        expected_revision is not None
        and artifact.source_revision is not None
        and artifact.source_revision != expected_revision
    ):
        return GuardResult(
            allowed=False,
            guard="revision_consistency",
            reason_code="ARTIFACT_REVISION_MISMATCH",
            message=(
                f"Artifact revision {artifact.source_revision!r} does not match "
                f"expected revision {expected_revision!r}."
            ),
            missing_requirements=["matching_source_revision"],
            evidence_ids=[artifact.artifact_id],
        )
    if reference_time is not None and ensure_utc(artifact.created_at) > ensure_utc(reference_time):
        return GuardResult(
            allowed=False,
            guard="evidence_existence",
            reason_code="FUTURE_EVIDENCE_TIMESTAMP",
            message="Artifact creation timestamp is in the future relative to evaluation time.",
            missing_requirements=["valid_evidence_timestamp"],
            evidence_ids=[artifact.artifact_id],
        )
    return GuardResult(
        allowed=True,
        guard="evidence_existence",
        reason_code="ARTIFACT_METADATA_VALID",
        message="Artifact metadata passed validation.",
        evidence_ids=[artifact.artifact_id],
    )


def collect_event_evidence_ids(event: IncidentEvent, context: TransitionContext) -> list[str]:
    """Gather all relevant evidence IDs referenced by an event and its context."""
    ids: list[str] = list(event.evidence_ids)
    if context.verification_result is not None:
        ids.extend(context.verification_result.artifact_ids)
    if context.mapping_result is not None:
        ids.extend(context.mapping_result.evidence_ids)
    if context.containment_proposal is not None:
        ids.extend(context.containment_proposal.evidence_ids)
    if context.operation_receipt is not None:
        ids.extend(context.operation_receipt.evidence_ids)
    if context.patch_test_result is not None:
        ids.extend(context.patch_test_result.artifact_ids)
    if context.deployment_evidence is not None:
        ids.extend(context.deployment_evidence.evidence_ids)
    if context.rollout_plan is not None:
        ids.extend(context.rollout_plan.evidence_ids)
    if context.rollback_proposal is not None:
        ids.extend(context.rollback_proposal.triggering_evidence_ids)
    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in ids:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
