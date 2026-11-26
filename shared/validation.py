"""Reusable validation rules for Killswitch X domain models and cross-model checks.

Security note on local vs. cross-service validation:
    Pydantic field validators verify local structural constraints (identifier format,
    hash format, safe relative paths, numeric ranges). Cross-service trust guarantees
    — such as verifying that an ``evidence_id`` actually exists in persistent storage
    for the target incident or that an ``ApprovalDecision`` was issued by an
    authenticated user session — MUST be enforced by the platform repositories and
    deterministic policy services rather than string checks alone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from shared.constants import IDENTIFIER_MAX_LENGTH, IDENTIFIER_MIN_LENGTH, SHA256_HEX_LENGTH
from shared.enums import ApprovalStatus
from shared.exceptions import (
    ArtifactValidationError,
    ContractValidationError,
    EvidenceValidationError,
    ExpiredApprovalError,
    InvalidApprovalError,
    PatchValidationError,
    RevisionMismatchError,
)
from shared.identifiers import ensure_utc, utc_now

if TYPE_CHECKING:
    from shared.schemas import (
        ApprovalDecision,
        ContainmentProposal,
        DependencyGraph,
        RolloutStage,
    )

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_SHA256_HEX_RE = re.compile(rf"^[0-9a-f]{{{SHA256_HEX_LENGTH}}}$")


def validate_non_empty_str(value: str, *, field_name: str) -> str:
    """Validate that a string is non-empty after stripping surrounding whitespace."""
    if not isinstance(value, str):
        raise ContractValidationError(
            f"{field_name} must be a string.",
            context={"field_name": field_name},
        )
    stripped = value.strip()
    if not stripped:
        raise ContractValidationError(
            f"{field_name} must be a non-empty string.",
            context={"field_name": field_name},
        )
    return stripped


def validate_identifier(value: str, *, field_name: str = "identifier") -> str:
    """Validate format and length bounds of a Killswitch X identifier."""
    cleaned = validate_non_empty_str(value, field_name=field_name)
    if not (IDENTIFIER_MIN_LENGTH <= len(cleaned) <= IDENTIFIER_MAX_LENGTH):
        raise ContractValidationError(
            f"{field_name} length must be between {IDENTIFIER_MIN_LENGTH} "
            f"and {IDENTIFIER_MAX_LENGTH} characters.",
            context={"field_name": field_name, "length": len(cleaned)},
        )
    if not _IDENTIFIER_RE.match(cleaned):
        raise ContractValidationError(
            f"{field_name} contains invalid characters; allowed: [A-Za-z0-9_.:-].",
            context={"field_name": field_name, "value": cleaned},
        )
    return cleaned


def validate_sha256_hex(value: str, *, field_name: str = "content_hash") -> str:
    """Validate a lowercase 64-character hexadecimal SHA-256 digest."""
    if not isinstance(value, str) or not _SHA256_HEX_RE.match(value):
        raise ArtifactValidationError(
            f"{field_name} must be a valid 64-character lowercase hexadecimal SHA-256 digest.",
            context={"field_name": field_name},
        )
    return value


def validate_utc_datetime(value: datetime, *, field_name: str = "timestamp") -> datetime:
    """Validate that a datetime is timezone-aware and normalized to UTC."""
    try:
        return ensure_utc(value)
    except ContractValidationError as exc:
        raise ContractValidationError(
            f"{field_name} must be a timezone-aware UTC datetime.",
            context={"field_name": field_name},
        ) from exc


def validate_unique_ids(ids: Iterable[str], *, field_name: str = "identifiers") -> list[str]:
    """Validate that a sequence of identifiers contains no duplicates."""
    seen: set[str] = set()
    ordered: list[str] = []
    for item in ids:
        validated = validate_identifier(item, field_name=field_name)
        if validated in seen:
            raise ContractValidationError(
                f"Duplicate identifier detected in {field_name}: {validated}",
                context={"field_name": field_name, "duplicate_id": validated},
            )
        seen.add(validated)
        ordered.append(validated)
    return ordered


def validate_relative_safe_path(path_value: str, *, field_name: str = "path") -> str:
    """Validate that a repository file path is relative and free of traversal segments."""
    cleaned = validate_non_empty_str(path_value, field_name=field_name)
    if "\\" in cleaned:
        raise PatchValidationError(
            f"{field_name} must use POSIX forward slashes and cannot contain backslashes.",
            context={"field_name": field_name, "path": cleaned},
        )
    if cleaned.startswith("/"):
        raise PatchValidationError(
            f"{field_name} must be repository-relative, not an absolute path.",
            context={"field_name": field_name, "path": cleaned},
        )
    posix_path = PurePosixPath(cleaned)
    if posix_path.is_absolute() or ".." in posix_path.parts or "." in posix_path.parts:
        raise PatchValidationError(
            f"{field_name} contains disallowed path traversal or dot segments.",
            context={"field_name": field_name, "path": cleaned},
        )
    return posix_path.as_posix()


def validate_touched_files_within_allowlist(
    touched_files: Sequence[str],
    allowed_files: Sequence[str],
) -> None:
    """Ensure every touched file in a patch proposal is explicitly allowlisted."""
    normalized_allowed = {
        validate_relative_safe_path(p, field_name="allowed_files") for p in allowed_files
    }
    if not normalized_allowed:
        raise PatchValidationError(
            "allowed_files must contain at least one safe relative path.",
            context={"allowed_files": []},
        )
    normalized_touched = [
        validate_relative_safe_path(p, field_name="touched_files") for p in touched_files
    ]
    if not normalized_touched:
        raise PatchValidationError(
            "touched_files must contain at least one safe relative path.",
            context={"touched_files": []},
        )
    disallowed = sorted(set(normalized_touched) - normalized_allowed)
    if disallowed:
        raise PatchValidationError(
            "Candidate patch touches files outside the approved file allowlist.",
            context={"disallowed_files": disallowed},
        )


def validate_revision_consistency(
    expected_revision: str,
    observed_revision: str,
    *,
    subject: str = "artifact",
) -> None:
    """Verify that observed source revision matches expected source revision."""
    expected = validate_non_empty_str(expected_revision, field_name="expected_revision")
    observed = validate_non_empty_str(observed_revision, field_name="observed_revision")
    if expected != observed:
        raise RevisionMismatchError(
            f"{subject} revision mismatch: expected {expected!r}, observed {observed!r}.",
            context={
                "subject": subject,
                "expected_revision": expected,
                "observed_revision": observed,
            },
        )


def validate_environment_consistency(
    expected_environment: str,
    observed_environment: str,
    *,
    subject: str = "operation",
) -> None:
    """Verify that target and observed environments match exactly."""
    expected = validate_non_empty_str(expected_environment, field_name="expected_environment")
    observed = validate_non_empty_str(observed_environment, field_name="observed_environment")
    if expected != observed:
        raise ContractValidationError(
            f"{subject} environment mismatch: expected {expected!r}, observed {observed!r}.",
            context={
                "subject": subject,
                "expected_environment": expected,
                "observed_environment": observed,
            },
        )


def validate_evidence_reference_ids(evidence_ids: Sequence[str]) -> list[str]:
    """Validate format and uniqueness of evidence reference identifiers."""
    return validate_unique_ids(evidence_ids, field_name="evidence_ids")


def require_evidence_references_present(
    evidence_ids: Sequence[str],
    *,
    context_label: str,
) -> list[str]:
    """Fail closed when required evidence references are missing or duplicated."""
    validated = validate_evidence_reference_ids(evidence_ids)
    if not validated:
        raise EvidenceValidationError(
            f"{context_label} requires at least one evidence reference.",
            context={"context_label": context_label},
        )
    return validated


def validate_proposal_hash_integrity(proposal: ContainmentProposal) -> None:
    """Verify that a ContainmentProposal's stored proposal_hash matches its canonical fields."""
    expected_hash = proposal.compute_hash()
    if proposal.proposal_hash != expected_hash:
        raise ContractValidationError(
            "ContainmentProposal hash does not match canonical proposal fields.",
            context={
                "proposal_id": proposal.proposal_id,
                "expected_hash": expected_hash,
                "actual_hash": proposal.proposal_hash,
            },
        )


def validate_approval_for_proposal(
    proposal: ContainmentProposal,
    approval: ApprovalDecision,
    *,
    reference_time: datetime | None = None,
) -> None:
    """Perform deterministic, fail-closed validation binding an approval to an exact proposal.

    Note:
        This validates structural identity, hash binding, decision status, and
        expiration against ``reference_time``. Cryptographic verification of
        ``authorization_context_ref`` and user session authentication remains the
        responsibility of the platform approval service.
    """
    validate_proposal_hash_integrity(proposal)
    now = ensure_utc(reference_time) if reference_time is not None else utc_now()

    if approval.proposal_id != proposal.proposal_id:
        raise InvalidApprovalError(
            "Approval proposal_id does not match target containment proposal.",
            context={
                "expected_proposal_id": proposal.proposal_id,
                "approval_proposal_id": approval.proposal_id,
            },
        )
    if approval.incident_id != proposal.incident_id:
        raise InvalidApprovalError(
            "Approval incident_id does not match target containment proposal.",
            context={
                "expected_incident_id": proposal.incident_id,
                "approval_incident_id": approval.incident_id,
            },
        )
    if approval.proposal_hash != proposal.proposal_hash:
        raise InvalidApprovalError(
            "Approval proposal_hash does not match canonical containment proposal hash.",
            context={
                "proposal_id": proposal.proposal_id,
                "expected_hash": proposal.proposal_hash,
                "approval_hash": approval.proposal_hash,
            },
        )
    if approval.decision != ApprovalStatus.APPROVED:
        raise InvalidApprovalError(
            f"Approval decision is {approval.decision.value!r}, not 'approved'.",
            context={"approval_id": approval.approval_id, "decision": approval.decision.value},
        )
    if approval.decided_at > now:
        raise InvalidApprovalError(
            "Approval timestamp is in the future relative to evaluation time.",
            context={"approval_id": approval.approval_id},
        )
    if approval.expires_at <= now or proposal.expires_at <= now:
        raise ExpiredApprovalError(
            "Approval or target proposal has expired.",
            context={
                "approval_id": approval.approval_id,
                "proposal_id": proposal.proposal_id,
            },
        )


def validate_rollout_stages_ordering(stages: Sequence[RolloutStage]) -> None:
    """Validate that rollout stages are non-empty, unique, and strictly increasing."""
    if not stages:
        raise ContractValidationError(
            "Rollout plan must define at least one rollout stage.",
            context={"stage_count": 0},
        )
    validate_unique_ids([s.stage_id for s in stages], field_name="stage_id")
    previous_pct = -1
    for stage in stages:
        if stage.exposure_percentage <= previous_pct:
            raise ContractValidationError(
                "Rollout stages must have strictly increasing exposure percentages.",
                context={
                    "stage_id": stage.stage_id,
                    "exposure_percentage": stage.exposure_percentage,
                    "previous_percentage": previous_pct,
                },
            )
        previous_pct = stage.exposure_percentage


def validate_dependency_graph_integrity(graph: DependencyGraph) -> None:
    """Validate that all graph node IDs are unique and all edges reference existing nodes."""
    node_ids = set(
        validate_unique_ids([node.node_id for node in graph.nodes], field_name="node_id")
    )
    for edge in graph.edges:
        if edge.source_id not in node_ids:
            raise ContractValidationError(
                f"Dependency graph edge references unknown source_id: {edge.source_id}",
                context={"source_id": edge.source_id, "target_id": edge.target_id},
            )
        if edge.target_id not in node_ids:
            raise ContractValidationError(
                f"Dependency graph edge references unknown target_id: {edge.target_id}",
                context={"source_id": edge.source_id, "target_id": edge.target_id},
            )
