"""Artifact metadata creation and SHA-256 integrity verification utilities.

Artifacts store evidence and candidate patches outside core incident records.
These helpers ensure artifact content digests match metadata before downstream
components rely on them.
"""

from __future__ import annotations

from collections.abc import Sequence

from shared.constants import HASH_ALGORITHM_SHA256
from shared.enums import ArtifactType, EvidenceProvenance, RedactionStatus
from shared.exceptions import ArtifactValidationError
from shared.identifiers import generate_artifact_id, utc_now
from shared.schemas import ArtifactReference
from shared.serialization import sha256_bytes
from shared.validation import validate_unique_ids


def build_artifact_reference(
    *,
    incident_id: str,
    artifact_type: ArtifactType,
    content: bytes,
    storage_ref: str,
    producer: str,
    provenance: EvidenceProvenance,
    content_type: str = "application/json",
    source_revision: str | None = None,
    redaction_status: RedactionStatus = RedactionStatus.REDACTED,
    artifact_id: str | None = None,
) -> ArtifactReference:
    """Construct an integrity-stamped ``ArtifactReference`` for raw artifact bytes."""
    return ArtifactReference(
        artifact_id=artifact_id or generate_artifact_id(),
        incident_id=incident_id,
        artifact_type=artifact_type,
        content_hash=sha256_bytes(content),
        hash_algorithm=HASH_ALGORITHM_SHA256,
        storage_ref=storage_ref,
        created_at=utc_now(),
        producer=producer,
        provenance=provenance,
        content_type=content_type,
        size_bytes=len(content),
        source_revision=source_revision,
        redaction_status=redaction_status,
    )


def verify_artifact_content_hash(reference: ArtifactReference, content: bytes) -> bool:
    """Return True iff the SHA-256 digest of ``content`` matches ``reference.content_hash``."""
    return sha256_bytes(content) == reference.content_hash


def require_artifact_integrity(reference: ArtifactReference, content: bytes) -> None:
    """Raise ``ArtifactValidationError`` if artifact bytes fail SHA-256 verification."""
    observed_hash = sha256_bytes(content)
    if observed_hash != reference.content_hash:
        raise ArtifactValidationError(
            "Artifact content SHA-256 digest does not match recorded metadata.",
            context={
                "artifact_id": reference.artifact_id,
                "expected_hash": reference.content_hash,
                "observed_hash": observed_hash,
            },
        )


def validate_artifact_collection(
    artifacts: Sequence[ArtifactReference],
    *,
    expected_incident_id: str | None = None,
) -> list[str]:
    """Validate unique artifact IDs and optional incident ownership consistency."""
    artifact_ids = validate_unique_ids(
        [a.artifact_id for a in artifacts], field_name="artifact_id"
    )
    if expected_incident_id is not None:
        for artifact in artifacts:
            if artifact.incident_id != expected_incident_id:
                raise ArtifactValidationError(
                    "Artifact belongs to a different incident than requested.",
                    context={
                        "artifact_id": artifact.artifact_id,
                        "expected_incident_id": expected_incident_id,
                        "artifact_incident_id": artifact.incident_id,
                    },
                )
    return artifact_ids
