"""Immutable Incident aggregate with versioned, transition-controlled updates.

State changes MUST happen via ``IncidentAggregate.with_transition(...)`` after
deterministic transition validation and guard evaluation. Direct mutation of
``current_state`` is prevented via ``frozen=True``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import ConfigDict, Field, StrictBool, StrictInt
from shared.enums import EvidenceProvenance, IncidentState
from shared.identifiers import utc_now
from shared.schemas import IdentifierStr, IncidentRecord, KillswitchModel, UtcDatetime

from agent_core.context import RolloutStageRecord


class IncidentAggregate(KillswitchModel):
    """Authoritative in-domain aggregate representing an incident's lifecycle state."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        ser_json_timedelta="iso8601",
    )

    incident_id: IdentifierStr
    finding_id: IdentifierStr
    environment: str = Field(min_length=1)
    source_revision: str | None = None
    current_state: IncidentState = IncidentState.RECEIVED
    incident_version: StrictInt = Field(default=1, ge=1)
    created_at: UtcDatetime = Field(default_factory=utc_now)
    updated_at: UtcDatetime = Field(default_factory=utc_now)

    # Proposal & approval tracking
    current_proposal_id: IdentifierStr | None = None
    current_proposal_hash: str | None = None
    superseded_proposal_ids: tuple[str, ...] = ()
    current_approval_id: IdentifierStr | None = None
    consumed_approval_ids: tuple[str, ...] = ()

    # Operation & readback tracking
    active_operation_id: IdentifierStr | None = None
    operation_idempotency_keys: tuple[str, ...] = ()
    observed_feature_state: StrictBool | None = None
    last_operation_timestamp: UtcDatetime | None = None

    # Investigation & mapping references
    mapping_result_id: IdentifierStr | None = None
    mapped_flag_name: str | None = None
    registry_version: str | None = None
    investigation_id: IdentifierStr | None = None

    # Verification & patching references
    verification_references: tuple[str, ...] = ()
    post_containment_verification_passed: StrictBool | None = None
    functional_smoke_test_passed: StrictBool | None = None
    patch_references: tuple[str, ...] = ()
    active_patch_id: IdentifierStr | None = None
    active_patch_hash: str | None = None
    deployment_references: tuple[str, ...] = ()
    verified_deployment_revision: str | None = None

    # Progressive rollout & rollback tracking
    active_rollout_plan_id: IdentifierStr | None = None
    current_rollout_stage: str | None = None
    rollout_stages: tuple[RolloutStageRecord, ...] = ()
    last_verified_safe_state: StrictBool | None = None
    last_verified_safe_state_known: StrictBool = False

    # Correlation, causality, diagnostics & provenance
    correlation_id: IdentifierStr
    latest_event_id: IdentifierStr
    latest_event_sequence: StrictInt = Field(default=1, ge=1)
    failure_reason: str | None = None
    failure_reason_code: str | None = None
    pending_action: str | None = None
    limitations: tuple[str, ...] = ()
    is_synthetic_fixture: StrictBool = False
    provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_OBSERVED

    def with_transition(
        self,
        *,
        new_state: IncidentState,
        event_id: str,
        event_sequence: int,
        updated_at: datetime,
        updates: dict[str, Any] | None = None,
    ) -> IncidentAggregate:
        """Return a new validated aggregate reflecting an accepted deterministic transition.

        Increments ``incident_version`` monotonically and updates ``latest_event_id``
        and ``latest_event_sequence``.
        """
        payload: dict[str, Any] = {
            "current_state": new_state,
            "incident_version": self.incident_version + 1,
            "latest_event_id": event_id,
            "latest_event_sequence": event_sequence,
            "updated_at": updated_at,
        }
        if updates:
            payload.update(updates)
        return self.model_copy(update=payload)

    def to_incident_record(self) -> IncidentRecord:
        """Project this aggregate into the shared persistence envelope ``IncidentRecord``."""
        return IncidentRecord(
            incident_id=self.incident_id,
            state=self.current_state,
            version=self.incident_version,
            environment=self.environment,
            primary_finding_id=self.finding_id,
            active_proposal_id=self.current_proposal_id,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
