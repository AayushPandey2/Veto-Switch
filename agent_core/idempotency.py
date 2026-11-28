"""Idempotency helpers distinguishing event, logical operation, and delivery identities."""

from __future__ import annotations

from shared.exceptions import IdempotencyConflictError
from shared.schemas import IncidentEvent
from shared.serialization import sha256_canonical

from agent_core.context import EventProcessingResult


def compute_event_payload_hash(event: IncidentEvent) -> str:
    """Compute canonical SHA-256 digest over an event's identity-bearing fields."""
    payload_obj = (
        event.payload.model_dump(mode="python")
        if hasattr(event.payload, "model_dump")
        else event.payload
    )
    if isinstance(payload_obj, dict) and "_replay_meta" in payload_obj:
        payload_obj = {k: v for k, v in payload_obj.items() if k != "_replay_meta"}
    return sha256_canonical(
        {
            "event_id": event.event_id,
            "incident_id": event.incident_id,
            "event_type": event.event_type.value,
            "actor": event.actor,
            "actor_type": event.actor_type.value,
            "evidence_ids": list(event.evidence_ids),
            "idempotency_token": event.idempotency_token,
            "payload": payload_obj,
        }
    )


def build_operation_idempotency_key(
    *,
    incident_id: str,
    proposal_id: str,
    approval_id: str,
    environment: str,
    target_feature: str,
    desired_enabled: bool,
    operation_kind: str = "flag_update",
    stage_id: str | None = None,
) -> str:
    """Derive a deterministic logical operation idempotency key.

    Note:
        Retrying delivery of the same authorized operation preserves the exact
        same key. Changing the proposal, approval, environment, feature, desired
        state, or rollout stage yields a distinct operation key.
    """
    digest = sha256_canonical(
        {
            "incident_id": incident_id,
            "proposal_id": proposal_id,
            "approval_id": approval_id,
            "environment": environment,
            "target_feature": target_feature,
            "desired_enabled": desired_enabled,
            "operation_kind": operation_kind,
            "stage_id": stage_id,
        }
    )
    return f"opkey_{digest[:32]}"


def check_event_idempotency(
    *,
    incoming_event: IncidentEvent,
    existing_event: IncidentEvent | None,
    existing_result: EventProcessingResult | None,
) -> EventProcessingResult | None:
    """Evaluate whether ``incoming_event`` is a safe duplicate or a conflicting replay.

    Returns:
        A duplicate ``EventProcessingResult`` if ``existing_event`` matches
        identically; ``None`` if ``incoming_event`` has not been seen before.

    Raises:
        IdempotencyConflictError: If ``event_id`` already exists with a different
            canonical payload or incident binding.
    """
    if existing_event is None:
        return None

    incoming_hash = compute_event_payload_hash(incoming_event)
    existing_hash = compute_event_payload_hash(existing_event)
    if incoming_hash != existing_hash:
        raise IdempotencyConflictError(
            f"Duplicate event_id {incoming_event.event_id!r} received with conflicting content.",
            context={
                "event_id": incoming_event.event_id,
                "incident_id": incoming_event.incident_id,
            },
        )

    if existing_result is not None:
        return existing_result.model_copy(
            update={
                "duplicate": True,
                "pending_requests": [],
                "reason_code": "DUPLICATE_EVENT_IGNORED",
            }
        )

    return EventProcessingResult(
        accepted=True,
        duplicate=True,
        incident_id=existing_event.incident_id,
        event_id=existing_event.event_id,
        previous_state=None,
        current_state=None,
        incident_version=0,
        generated_events=[],
        pending_requests=[],
        guard_failures=[],
        reason_code="DUPLICATE_EVENT_IGNORED",
        retryable=False,
    )
