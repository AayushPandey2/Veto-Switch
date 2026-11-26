"""Collision-resistant identifier and UTC timestamp utilities.

Note on trust boundaries:
    Locally generated identifiers (including idempotency tokens) are correlation
    and deduplication handles only — they are NEVER authorization credentials.

Future persistence & concurrency requirements (documented for Phase 02+):
    - Transactional event persistence: events must be committed atomically with
      incident state updates inside a single database transaction.
    - Idempotency enforcement: duplicate ``idempotency_token`` or ``event_id``
      submissions must be rejected or deduplicated by unique storage constraints.
    - Concurrent state updates: optimistic concurrency control via incident
      ``version`` must prevent lost updates across parallel workers.
    - Approval invalidation: any change to proposal target, state, or incident
      revision must invalidate prior approvals immediately.
    - Event ordering & replay: monotonic per-incident ``sequence_number`` values
      must support deterministic replay and audit verification.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from shared.constants import ID_PREFIXES
from shared.exceptions import ContractValidationError


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(tz=UTC)


def ensure_utc(value: datetime) -> datetime:
    """Validate that a datetime is timezone-aware and normalize it to UTC.

    Naive datetimes are rejected strictly to avoid ambiguous timezone coercion.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContractValidationError(
            "Naive datetimes are not permitted; timestamps must include explicit UTC offset.",
            context={"received": value.isoformat()},
        )
    return value.astimezone(UTC)


def format_utc_iso(value: datetime) -> str:
    """Format a timezone-aware datetime as canonical ISO-8601 UTC with ``Z`` suffix."""
    normalized = ensure_utc(value)
    return normalized.isoformat().replace("+00:00", "Z")


def generate_prefixed_id(entity_kind: str) -> str:
    """Generate a collision-resistant UUIDv4-based identifier with a standard prefix."""
    prefix = ID_PREFIXES.get(entity_kind)
    if prefix is None:
        raise ContractValidationError(
            f"Unknown entity kind for identifier generation: {entity_kind!r}",
            context={"entity_kind": entity_kind},
        )
    return f"{prefix}_{uuid.uuid4().hex}"


def generate_incident_id() -> str:
    return generate_prefixed_id("incident")


def generate_finding_id() -> str:
    return generate_prefixed_id("finding")


def generate_investigation_id() -> str:
    return generate_prefixed_id("investigation")


def generate_option_id() -> str:
    return generate_prefixed_id("option")


def generate_proposal_id() -> str:
    return generate_prefixed_id("proposal")


def generate_approval_id() -> str:
    return generate_prefixed_id("approval")


def generate_operation_id() -> str:
    return generate_prefixed_id("operation")


def generate_verification_id() -> str:
    return generate_prefixed_id("verification")


def generate_event_id() -> str:
    return generate_prefixed_id("event")


def generate_patch_id() -> str:
    return generate_prefixed_id("patch")


def generate_artifact_id() -> str:
    return generate_prefixed_id("artifact")


def generate_test_run_id() -> str:
    return generate_prefixed_id("test_run")


def generate_deployment_id() -> str:
    return generate_prefixed_id("deployment")


def generate_rollout_plan_id() -> str:
    return generate_prefixed_id("rollout_plan")


def generate_rollout_stage_id() -> str:
    return generate_prefixed_id("rollout_stage")


def generate_rollout_decision_id() -> str:
    return generate_prefixed_id("rollout_decision")


def generate_rollback_id() -> str:
    return generate_prefixed_id("rollback")


def generate_metric_snapshot_id() -> str:
    return generate_prefixed_id("metric_snapshot")


def generate_coverage_finding_id() -> str:
    return generate_prefixed_id("coverage_finding")


def generate_report_id() -> str:
    return generate_prefixed_id("report")


def generate_correlation_id() -> str:
    return generate_prefixed_id("correlation")


def generate_idempotency_token() -> str:
    return generate_prefixed_id("idempotency")
