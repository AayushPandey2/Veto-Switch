"""Exact-action approval binding and pre-execution state-drift revalidation."""

from __future__ import annotations

from datetime import datetime

from agent_core.context import GuardResult, ProducerContext
from shared.enums import (
    ActorType,
    ApprovalStatus,
    FeatureObservationStatus,
    RollbackReasonCode,
)
from shared.identifiers import ensure_utc, utc_now
from shared.schemas import (
    ApprovalDecision,
    FeatureState,
    RollbackProposal,
)


def validate_rollback_approval_binding(
    *,
    proposal: RollbackProposal,
    approval: ApprovalDecision | None,
    producer: ProducerContext,
    consumed_approval_ids: set[str] | None = None,
    reference_time: datetime | None = None,
) -> GuardResult:
    """Bind fresh human approval to exact RollbackProposal identity and canonical hash."""
    now = ensure_utc(reference_time) if reference_time is not None else utc_now()

    if not producer.authenticated or producer.actor_type != ActorType.HUMAN_OPERATOR:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="UNAUTHENTICATED_OR_NON_HUMAN_APPROVER",
            message="Rollback approval requires authenticated HUMAN_OPERATOR.",
            missing_requirements=["authenticated_human_operator"],
        )
    if approval is None:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code=RollbackReasonCode.APPROVAL_REQUIRED.value,
            message="Fresh human ApprovalDecision is required for rollback.",
            missing_requirements=["rollback_approval_decision"],
        )
    if approval.incident_id != proposal.incident_id:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="APPROVAL_INCIDENT_MISMATCH",
            message="Approval incident_id does not match RollbackProposal.",
            missing_requirements=["matching_incident_approval"],
        )
    if approval.proposal_id != proposal.proposal_id:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="ROLLBACK_PROPOSAL_ID_MISMATCH",
            message="Approval proposal_id does not match RollbackProposal.",
            missing_requirements=["matching_rollback_proposal_id"],
        )
    expected_hash = proposal.compute_canonical_hash()
    if proposal.proposal_hash != expected_hash or approval.proposal_hash != expected_hash:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code=RollbackReasonCode.PROPOSAL_HASH_MISMATCH.value,
            message="Approval proposal_hash does not match canonical RollbackProposal hash.",
            missing_requirements=["matching_proposal_hash"],
        )
    if approval.decision != ApprovalStatus.APPROVED:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="APPROVAL_NOT_APPROVED",
            message=f"Approval decision is {approval.decision.value!r}, not 'approved'.",
            missing_requirements=["approved_decision"],
        )
    if approval.expires_at <= now or (
        proposal.expires_at is not None and proposal.expires_at <= now
    ):
        return GuardResult(
            allowed=False,
            guard="approval_freshness",
            reason_code=RollbackReasonCode.APPROVAL_EXPIRED.value,
            message="Rollback approval or proposal has expired.",
            missing_requirements=["fresh_rollback_approval"],
        )
    if approval.decided_at > now:
        return GuardResult(
            allowed=False,
            guard="approval_freshness",
            reason_code="FUTURE_APPROVAL_TIMESTAMP",
            message="Approval timestamp is in the future.",
            missing_requirements=["valid_approval_timestamp"],
        )
    if consumed_approval_ids and approval.approval_id in consumed_approval_ids:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code=RollbackReasonCode.APPROVAL_ALREADY_CONSUMED.value,
            message="Approval has already been consumed and cannot be reused.",
            missing_requirements=["fresh_unconsumed_approval"],
        )
    return GuardResult(
        allowed=True,
        guard="approval_validity",
        reason_code="ROLLBACK_APPROVAL_VERIFIED",
        message="Fresh human approval verified against canonical RollbackProposal hash.",
    )


def revalidate_rollback_preconditions(
    *,
    proposal: RollbackProposal,
    observed_feature_state: FeatureState | None,
    observed_targeting_version: str | None = None,
    observed_deployment_identity: str | None = None,
) -> GuardResult:
    """Detect state drift between proposal creation and execution."""
    if (
        observed_feature_state is None
        or observed_feature_state.observation_status != FeatureObservationStatus.OBSERVED
    ):
        return GuardResult(
            allowed=False,
            guard="feature_state_freshness",
            reason_code=RollbackReasonCode.CURRENT_STATE_UNKNOWN.value,
            message="Current feature state must be OBSERVED before rollback execution.",
            missing_requirements=["observed_feature_state"],
        )
    if (
        observed_feature_state.environment != proposal.target_environment
        or observed_feature_state.feature_name != proposal.target_feature
    ):
        return GuardResult(
            allowed=False,
            guard="environment_consistency",
            reason_code="FEATURE_STATE_TARGET_MISMATCH",
            message="Observed FeatureState target does not match RollbackProposal.",
            missing_requirements=["matching_feature_state"],
        )
    if (
        proposal.current_state is not None
        and observed_feature_state.enabled != proposal.current_state
    ):
        return GuardResult(
            allowed=False,
            guard="feature_state_freshness",
            reason_code=RollbackReasonCode.CURRENT_TARGETING_CONFLICT.value,
            message=(
                f"State drift detected: expected enabled={proposal.current_state}, "
                f"observed={observed_feature_state.enabled}."
            ),
            missing_requirements=["reconciled_proposal_and_fresh_approval"],
        )
    if (
        proposal.expected_targeting_version is not None
        and observed_targeting_version is not None
        and observed_targeting_version != proposal.expected_targeting_version
    ):
        return GuardResult(
            allowed=False,
            guard="feature_state_freshness",
            reason_code=RollbackReasonCode.CURRENT_TARGETING_CONFLICT.value,
            message=(
                f"Targeting version drifted from {proposal.expected_targeting_version!r} "
                f"to {observed_targeting_version!r}."
            ),
            missing_requirements=["reconciled_targeting_version"],
        )
    if (
        proposal.deployment_identity is not None
        and observed_deployment_identity is not None
        and observed_deployment_identity != proposal.deployment_identity
    ):
        return GuardResult(
            allowed=False,
            guard="revision_consistency",
            reason_code=RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH.value,
            message="Deployment identity changed before rollback execution.",
            missing_requirements=["revalidated_deployment_identity"],
        )
    return GuardResult(
        allowed=True,
        guard="feature_state_freshness",
        reason_code="ROLLBACK_PRECONDITIONS_VERIFIED",
        message="Pre-execution state preconditions match RollbackProposal.",
    )
