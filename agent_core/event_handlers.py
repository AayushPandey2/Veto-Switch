"""Individual, unit-testable domain event handlers emitting non-privileged requests."""

from __future__ import annotations

from typing import Protocol

from shared.enums import EventType
from shared.identifiers import generate_prefixed_id
from shared.schemas import IncidentEvent

from agent_core.context import DownstreamRequest, TransitionContext
from agent_core.idempotency import build_operation_idempotency_key
from agent_core.incident import IncidentAggregate


class EventHandler(Protocol):
    """Contract for individual event handlers producing permitted downstream requests."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]: ...


def _is_fixture(incident: IncidentAggregate, context: TransitionContext) -> bool:
    return bool(
        context.fixture_mode
        or incident.is_synthetic_fixture
        or context.producer_context.provenance_mode == "fixture"
    )


class VerificationRequestedHandler:
    """Emits an authorized verification request for SecurityVerifier."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        is_fixture = _is_fixture(updated_incident, context)
        return [
            DownstreamRequest(
                request_id=f"req_{generate_prefixed_id('verification')}",
                request_type="security_verification_request",
                incident_id=updated_incident.incident_id,
                environment=updated_incident.environment,
                executable_live=not is_fixture,
                is_synthetic_fixture=is_fixture,
                metadata={
                    "finding_id": updated_incident.finding_id,
                    "source_revision": updated_incident.source_revision,
                    "phase": "before_containment",
                },
            )
        ]


class ApprovalGrantedHandler:
    """Emits an authorized, non-executing Flagsmith operation request for the platform layer."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        proposal = context.active_proposal or context.containment_proposal
        approval = context.approval_decision
        if proposal is None or approval is None:
            return []
        is_fixture = _is_fixture(updated_incident, context)
        idem_key = build_operation_idempotency_key(
            incident_id=updated_incident.incident_id,
            proposal_id=proposal.proposal_id,
            approval_id=approval.approval_id,
            environment=proposal.environment,
            target_feature=proposal.flag_name,
            desired_enabled=proposal.desired_enabled,
            operation_kind="containment_flag_update",
        )
        return [
            DownstreamRequest(
                request_id=f"req_{generate_prefixed_id('operation')}",
                request_type="platform_flag_execution_request",
                incident_id=updated_incident.incident_id,
                proposal_id=proposal.proposal_id,
                approval_id=approval.approval_id,
                operation_id=updated_incident.active_operation_id,
                idempotency_key=idem_key,
                environment=proposal.environment,
                target_feature=proposal.flag_name,
                desired_enabled=proposal.desired_enabled,
                executable_live=not is_fixture,
                is_synthetic_fixture=is_fixture,
                metadata={
                    "proposal_hash": proposal.proposal_hash,
                    "registry_version": proposal.registry_version,
                },
            )
        ]


class FlagUpdateSuccessHandler:
    """Emits readback + post-containment verification request after executor success."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        is_fixture = _is_fixture(updated_incident, context)
        return [
            DownstreamRequest(
                request_id=f"req_{generate_prefixed_id('verification')}",
                request_type="post_containment_verification_request",
                incident_id=updated_incident.incident_id,
                operation_id=updated_incident.active_operation_id,
                environment=updated_incident.environment,
                target_feature=updated_incident.mapped_flag_name,
                executable_live=not is_fixture,
                is_synthetic_fixture=is_fixture,
                metadata={"phase": "after_containment"},
            )
        ]


class UnknownOutcomeReconciliationHandler:
    """Emits a read-only reconciliation request when external write outcome is unknown."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        is_fixture = _is_fixture(updated_incident, context)
        return [
            DownstreamRequest(
                request_id=f"req_{generate_prefixed_id('operation')}",
                request_type="reconcile_operation_and_feature_state",
                incident_id=updated_incident.incident_id,
                operation_id=updated_incident.active_operation_id,
                environment=updated_incident.environment,
                target_feature=updated_incident.mapped_flag_name,
                executable_live=not is_fixture,
                is_synthetic_fixture=is_fixture,
                metadata={"reason": "unknown_external_write_outcome"},
            )
        ]


class RolloutStageApprovedHandler:
    """Emits stage-specific platform rollout execution request after fresh stage approval."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        approval = context.stage_approval_decision or context.approval_decision
        if approval is None:
            return []
        is_fixture = _is_fixture(updated_incident, context)
        stage_id = updated_incident.current_rollout_stage or approval.proposal_id
        target_feature = updated_incident.mapped_flag_name or "search_v2"
        idem_key = build_operation_idempotency_key(
            incident_id=updated_incident.incident_id,
            proposal_id=updated_incident.active_rollout_plan_id or approval.proposal_id,
            approval_id=approval.approval_id,
            environment=updated_incident.environment,
            target_feature=target_feature,
            desired_enabled=True,
            operation_kind="rollout_stage_update",
            stage_id=stage_id,
        )
        return [
            DownstreamRequest(
                request_id=f"req_{generate_prefixed_id('rollout_stage')}",
                request_type="platform_rollout_stage_execution_request",
                incident_id=updated_incident.incident_id,
                proposal_id=updated_incident.active_rollout_plan_id or approval.proposal_id,
                approval_id=approval.approval_id,
                idempotency_key=idem_key,
                environment=updated_incident.environment,
                target_feature=target_feature,
                desired_enabled=True,
                executable_live=not is_fixture,
                is_synthetic_fixture=is_fixture,
                metadata={"stage_id": stage_id},
            )
        ]


class RollbackApprovedHandler:
    """Emits platform rollback execution request only after explicit human rollback approval."""

    def handle(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        approval = context.stage_approval_decision or context.approval_decision
        rb = context.rollback_proposal
        if approval is None or rb is None:
            return []
        is_fixture = _is_fixture(updated_incident, context)
        idem_key = build_operation_idempotency_key(
            incident_id=updated_incident.incident_id,
            proposal_id=rb.proposal_id,
            approval_id=approval.approval_id,
            environment=rb.target_environment,
            target_feature=rb.target_feature,
            desired_enabled=rb.proposed_state,
            operation_kind="rollback_flag_update",
        )
        return [
            DownstreamRequest(
                request_id=f"req_{generate_prefixed_id('rollback')}",
                request_type="platform_rollback_execution_request",
                incident_id=updated_incident.incident_id,
                proposal_id=rb.proposal_id,
                approval_id=approval.approval_id,
                idempotency_key=idem_key,
                environment=rb.target_environment,
                target_feature=rb.target_feature,
                desired_enabled=rb.proposed_state,
                executable_live=not is_fixture,
                is_synthetic_fixture=is_fixture,
                metadata={"rollback_proposal_id": rb.proposal_id},
            )
        ]


DEFAULT_EVENT_HANDLERS: dict[EventType, EventHandler] = {
    EventType.VERIFICATION_REQUESTED: VerificationRequestedHandler(),
    EventType.VALIDATION_REQUESTED: VerificationRequestedHandler(),
    EventType.APPROVAL_GRANTED: ApprovalGrantedHandler(),
    EventType.FLAG_UPDATE_SUCCESS: FlagUpdateSuccessHandler(),
    EventType.FLAG_CHANGE_EXECUTED: FlagUpdateSuccessHandler(),
    EventType.FLAG_UPDATE_OUTCOME_UNKNOWN: UnknownOutcomeReconciliationHandler(),
    EventType.ROLLOUT_STAGE_APPROVED: RolloutStageApprovedHandler(),
    EventType.ROLLBACK_APPROVED: RollbackApprovedHandler(),
}
