"""Event classification, construction, ordering, and causality validation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from shared.enums import ActorType, EventType
from shared.exceptions import ContractValidationError, InvalidTransitionError
from shared.identifiers import (
    generate_correlation_id,
    generate_event_id,
    generate_idempotency_token,
    utc_now,
)
from shared.schemas import IncidentEvent, TypedEventPayload

from agent_core.incident import IncidentAggregate


class EventClassification(StrEnum):
    """Distinguishes authoritative domain events from commands and incoming notifications."""

    DOMAIN_EVENT = "domain_event"
    COMMAND = "command"
    EXTERNAL_NOTIFICATION = "external_notification"
    INTERNAL_DECISION = "internal_decision"
    REJECTED_DIAGNOSTIC = "rejected_diagnostic"


_EVENT_CLASSIFICATION: dict[EventType, EventClassification] = {
    EventType.VERIFICATION_REQUESTED: EventClassification.COMMAND,
    EventType.VALIDATION_REQUESTED: EventClassification.COMMAND,
    EventType.INVESTIGATION_REQUESTED: EventClassification.COMMAND,
    EventType.MAPPING_REQUESTED: EventClassification.COMMAND,
    EventType.APPROVAL_REQUESTED: EventClassification.COMMAND,
    EventType.EXECUTION_REQUESTED: EventClassification.COMMAND,
    EventType.CONTAINMENT_VERIFICATION_REQUESTED: EventClassification.COMMAND,
    EventType.PATCH_REQUESTED: EventClassification.COMMAND,
    EventType.PATCH_TEST_REQUESTED: EventClassification.COMMAND,
    EventType.REPRODUCTION_CONFIRMED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.VULNERABILITY_REPRODUCED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.REPRODUCTION_NOT_CONFIRMED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.VERIFICATION_INCONCLUSIVE: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.VERIFICATION_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.VERIFICATION_TIMEOUT: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.APPROVAL_GRANTED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.APPROVAL_REJECTED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.APPROVAL_RECORDED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FLAG_UPDATE_SUCCESS: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FLAG_CHANGE_EXECUTED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FLAG_UPDATE_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FLAG_CHANGE_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FLAG_UPDATE_OUTCOME_UNKNOWN: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FLAG_STATE_OBSERVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.CONTAINMENT_VERIFICATION_PASSED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.CONTAINMENT_VERIFICATION_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FUNCTIONAL_SMOKE_TEST_PASSED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.FUNCTIONAL_SMOKE_TEST_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.PATCH_TEST_PASSED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.PATCH_TEST_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.PATCH_TEST_INFRASTRUCTURE_ERROR: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.DEPLOYMENT_OBSERVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.PATCH_DEPLOYMENT_OBSERVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLOUT_STAGE_APPROVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLOUT_STAGE_APPLIED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLOUT_STAGE_OBSERVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLOUT_METRICS_RECEIVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLBACK_APPROVED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLBACK_REJECTED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLBACK_APPLIED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLBACK_VERIFICATION_PASSED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.ROLLBACK_VERIFICATION_FAILED: EventClassification.EXTERNAL_NOTIFICATION,
    EventType.CONTAINMENT_PROPOSED: EventClassification.INTERNAL_DECISION,
    EventType.ROLLOUT_PLAN_CREATED: EventClassification.INTERNAL_DECISION,
    EventType.ROLLOUT_STAGE_PROPOSED: EventClassification.INTERNAL_DECISION,
    EventType.ROLLOUT_ADVANCE_PROPOSED: EventClassification.INTERNAL_DECISION,
    EventType.ROLLOUT_HOLD: EventClassification.INTERNAL_DECISION,
    EventType.ROLLBACK_PROPOSED: EventClassification.INTERNAL_DECISION,
}

# Events that require causal linkage when an active causal predecessor exists.
_CAUSATION_REQUIRED_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.APPROVAL_GRANTED,
        EventType.APPROVAL_REJECTED,
        EventType.FLAG_UPDATE_SUCCESS,
        EventType.FLAG_UPDATE_FAILED,
        EventType.CONTAINMENT_CONFIRMED,
        EventType.CONTAINMENT_VERIFIED,
    }
)


def classify_event(event_type: EventType) -> EventClassification:
    """Return the architectural classification for ``event_type``."""
    return _EVENT_CLASSIFICATION.get(event_type, EventClassification.DOMAIN_EVENT)


def build_incident_event(
    *,
    incident_id: str,
    event_type: EventType,
    actor: str,
    actor_type: ActorType,
    sequence_number: int,
    correlation_id: str | None = None,
    causation_id: str | None = None,
    evidence_ids: list[str] | None = None,
    payload: TypedEventPayload | None = None,
    timestamp_utc: datetime | None = None,
    event_id: str | None = None,
    idempotency_token: str | None = None,
) -> IncidentEvent:
    """Construct a schema-validated ``IncidentEvent`` with collision-resistant IDs."""
    return IncidentEvent(
        event_id=event_id or generate_event_id(),
        incident_id=incident_id,
        event_type=event_type,
        actor=actor,
        actor_type=actor_type,
        timestamp_utc=timestamp_utc or utc_now(),
        correlation_id=correlation_id or generate_correlation_id(),
        causation_id=causation_id,
        sequence_number=sequence_number,
        evidence_ids=evidence_ids or [],
        idempotency_token=idempotency_token or generate_idempotency_token(),
        payload=payload if payload is not None else {},
    )


def validate_event_ordering_and_causality(
    incident: IncidentAggregate,
    event: IncidentEvent,
) -> None:
    """Validate monotonic sequence ordering, correlation, and causality links.

    Raises:
        InvalidTransitionError: If ``sequence_number`` is out of order,
            correlation does not match, or required causation is missing.
    """
    expected_seq = incident.latest_event_sequence + 1
    if event.sequence_number != expected_seq:
        raise InvalidTransitionError(
            f"Out-of-order event sequence: expected {expected_seq}, got {event.sequence_number}.",
            context={
                "incident_id": incident.incident_id,
                "expected_sequence": expected_seq,
                "actual_sequence": event.sequence_number,
                "event_type": event.event_type.value,
            },
        )

    if event.correlation_id != incident.correlation_id:
        raise ContractValidationError(
            "Event correlation_id does not match incident correlation_id.",
            context={
                "incident_id": incident.incident_id,
                "expected_correlation_id": incident.correlation_id,
                "actual_correlation_id": event.correlation_id,
            },
        )

    if event.event_type in _CAUSATION_REQUIRED_EVENTS and not event.causation_id:
        raise InvalidTransitionError(
            f"Event {event.event_type.value!r} requires an explicit causation_id.",
            context={"incident_id": incident.incident_id, "event_id": event.event_id},
        )


def enrich_replay_payload(
    event: IncidentEvent,
    *,
    extra: dict[str, Any],
) -> IncidentEvent:
    """Attach deterministic replay metadata under ``_replay_meta`` without altering caller hash."""
    if isinstance(event.payload, dict):
        merged = dict(event.payload)
        meta = dict(merged.get("_replay_meta", {}))
        for k, v in extra.items():
            if v is not None and k not in meta:
                meta[k] = v
        if meta:
            merged["_replay_meta"] = meta
        return event.model_copy(update={"payload": merged})
    return event
