"""Unit tests for identifiers, UTC timestamps, canonical hashing, and artifacts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from shared.artifacts import (
    build_artifact_reference,
    require_artifact_integrity,
    validate_artifact_collection,
    verify_artifact_content_hash,
)
from shared.enums import ArtifactType, EvidenceProvenance
from shared.exceptions import ArtifactValidationError, ContractValidationError
from shared.identifiers import (
    ensure_utc,
    format_utc_iso,
    generate_incident_id,
    generate_proposal_id,
)
from shared.schemas import ArtifactReference, ContainmentProposal
from shared.serialization import canonical_json, from_json, to_json
from shared.validation import validate_unique_ids


@pytest.mark.unit
def test_generated_ids_are_unique_and_prefixed() -> None:
    ids = {generate_incident_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(item.startswith("inc_") for item in ids)
    assert generate_proposal_id().startswith("prop_")


@pytest.mark.unit
def test_utc_timestamp_normalization_and_naive_rejection() -> None:
    """Scenario 5: UTC timestamps serialize consistently and naive datetimes fail."""
    offset_tz = timezone(timedelta(hours=5, minutes=30))
    aware_ist = datetime(2026, 11, 26, 5, 30, 0, tzinfo=offset_tz)
    normalized = ensure_utc(aware_ist)
    assert normalized.tzinfo == UTC
    assert format_utc_iso(aware_ist) == "2026-11-26T00:00:00Z"

    naive = datetime(2026, 11, 26, 5, 30, 0)
    with pytest.raises(ContractValidationError):
        ensure_utc(naive)


@pytest.mark.unit
def test_canonical_json_and_proposal_hash_determinism(
    sample_containment_proposal: ContainmentProposal,
) -> None:
    """Scenarios 13 & 14: Proposal hash is deterministic and sensitive to security fields."""
    assert canonical_json({"b": 1, "a": {"d": 4, "c": 3}}) == '{"a":{"c":3,"d":4},"b":1}'
    hash1 = sample_containment_proposal.compute_hash()
    hash2 = sample_containment_proposal.compute_hash()
    assert hash1 == hash2 == sample_containment_proposal.proposal_hash

    mutated_flag = sample_containment_proposal.model_copy(update={"flag_name": "files_v1"})
    assert mutated_flag.compute_hash() != hash1

    mutated_state = sample_containment_proposal.model_copy(update={"desired_enabled": True})
    assert mutated_state.compute_hash() != hash1

    mutated_env = sample_containment_proposal.model_copy(update={"environment": "production"})
    assert mutated_env.compute_hash() != hash1


@pytest.mark.unit
def test_serialization_roundtrip_preserves_data(
    sample_containment_proposal: ContainmentProposal,
) -> None:
    """Scenario 25: JSON serialization and deserialization preserve model fidelity."""
    raw = to_json(sample_containment_proposal)
    restored = from_json(ContainmentProposal, raw)
    assert restored == sample_containment_proposal
    assert restored.verify_hash() is True


@pytest.mark.unit
def test_artifact_hash_validation_and_integrity_checks() -> None:
    """Scenario 12: Malformed SHA-256 hashes and tampered contents are rejected."""
    payload = b'{"test": "ok"}'
    ref = build_artifact_reference(
        incident_id="inc_00000000000000000000000000000001",
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content=payload,
        storage_ref="artifacts/inc_1/repro.json",
        producer="test_suite",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    assert verify_artifact_content_hash(ref, payload) is True
    require_artifact_integrity(ref, payload)

    with pytest.raises(ArtifactValidationError):
        require_artifact_integrity(ref, b'{"test": "tampered"}')

    with pytest.raises((ValidationError, ArtifactValidationError)):
        ArtifactReference(
            artifact_id="art_bad_hash",
            incident_id="inc_00000000000000000000000000000001",
            artifact_type=ArtifactType.REPRODUCTION_LOG,
            content_hash="abc123",
            storage_ref="artifacts/bad.json",
            producer="test_suite",
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
            content_type="application/json",
        )

    assert validate_artifact_collection([ref], expected_incident_id=ref.incident_id) == [
        ref.artifact_id
    ]
    with pytest.raises(ArtifactValidationError):
        validate_artifact_collection([ref], expected_incident_id="inc_other_0001")


@pytest.mark.unit
def test_duplicate_identifier_detection() -> None:
    """Scenario 28: Duplicate identifiers are rejected."""
    with pytest.raises(ContractValidationError):
        validate_unique_ids(["art_0001", "art_0001"], field_name="evidence_ids")
