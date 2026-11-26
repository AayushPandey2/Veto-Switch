"""Human approval identity, freshness, and single-use validation."""

from __future__ import annotations

from shared.enums import ActorType, ApprovalStatus, FeatureObservationStatus
from shared.exceptions import ExpiredApprovalError, InvalidApprovalError
from shared.schemas import (
    ApprovalDecision,
    ContainmentProposal,
    FeatureState,
    RouteFlagRegistry,
)
from shared.validation import validate_approval_for_proposal

from agent_core.context import Clock, GuardResult, ProducerContext, SystemClock
from agent_core.incident import IncidentAggregate


class ApprovalValidator:
    """Security-sensitive validator binding human approvals to exact proposals."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        route_registry: RouteFlagRegistry | None = None,
    ) -> None:
        self._clock: Clock = clock or SystemClock()
        self._route_registry = route_registry

    def validate_containment_approval(
        self,
        *,
        incident: IncidentAggregate,
        proposal: ContainmentProposal | None,
        approval: ApprovalDecision | None,
        producer: ProducerContext,
        feature_state: FeatureState | None,
        consumed_approval_ids: set[str] | None = None,
        route_registry: RouteFlagRegistry | None = None,
    ) -> list[GuardResult]:
        """Evaluate identity, authenticity, freshness, and feature-state alignment."""
        results: list[GuardResult] = []
        now = self._clock.now()
        registry = route_registry or self._route_registry

        # 1. Producer must be an authenticated human operator (never an AI agent).
        if not producer.authenticated or producer.actor_type != ActorType.HUMAN_OPERATOR:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="approval_validity",
                    reason_code="UNAUTHENTICATED_OR_NON_HUMAN_APPROVER",
                    message=(
                        "Approval requires an authenticated HUMAN_OPERATOR producer; "
                        f"received actor_type={producer.actor_type.value!r}, "
                        f"authenticated={producer.authenticated}."
                    ),
                    missing_requirements=["authenticated_human_operator"],
                )
            )
            return results

        if proposal is None:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="proposal_integrity",
                    reason_code="MISSING_ACTIVE_PROPOSAL",
                    message="No active containment proposal exists for approval.",
                    missing_requirements=["active_containment_proposal"],
                )
            )
            return results

        if approval is None:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="approval_validity",
                    reason_code="MISSING_APPROVAL_DECISION",
                    message="Approval decision record is missing.",
                    missing_requirements=["approval_decision"],
                )
            )
            return results

        # 2. Proposal must still be the active non-superseded proposal on this incident.
        if (
            incident.current_proposal_id is not None
            and proposal.proposal_id != incident.current_proposal_id
        ) or proposal.proposal_id in incident.superseded_proposal_ids:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="approval_validity",
                    reason_code="SUPERSEDED_PROPOSAL",
                    message="Approval references a superseded or inactive proposal.",
                    missing_requirements=["active_proposal_match"],
                )
            )
            return results

        if (
            incident.current_proposal_hash is not None
            and proposal.proposal_hash != incident.current_proposal_hash
        ):
            results.append(
                GuardResult(
                    allowed=False,
                    guard="proposal_integrity",
                    reason_code="PROPOSAL_HASH_DRIFT",
                    message="Active incident proposal hash does not match provided proposal.",
                    missing_requirements=["matching_proposal_hash"],
                )
            )
            return results

        # 3. Single-use approval consumption check.
        all_consumed = set(incident.consumed_approval_ids)
        if consumed_approval_ids:
            all_consumed.update(consumed_approval_ids)
        if approval.approval_id in all_consumed:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="approval_validity",
                    reason_code="APPROVAL_ALREADY_CONSUMED",
                    message=(
                        f"Approval {approval.approval_id!r} has already been consumed "
                        "by a prior operation."
                    ),
                    missing_requirements=["fresh_unconsumed_approval"],
                )
            )
            return results

        # 4. Registry & environment allowlist checks.
        if registry is not None:
            if proposal.environment != registry.environment:
                results.append(
                    GuardResult(
                        allowed=False,
                        guard="environment_consistency",
                        reason_code="UNAUTHORIZED_ENVIRONMENT",
                        message=(
                            f"Proposal environment {proposal.environment!r} does not match "
                            f"authorized registry environment {registry.environment!r}."
                        ),
                        missing_requirements=["authorized_environment"],
                    )
                )
                return results
            if proposal.flag_name not in registry.declared_features:
                results.append(
                    GuardResult(
                        allowed=False,
                        guard="registry_validity",
                        reason_code="UNKNOWN_FEATURE_FLAG",
                        message=(
                            f"Target feature {proposal.flag_name!r} is not declared in "
                            f"registry {registry.registry_version!r}."
                        ),
                        missing_requirements=["allowlisted_feature_flag"],
                    )
                )
                return results
            if proposal.registry_version != registry.registry_version:
                results.append(
                    GuardResult(
                        allowed=False,
                        guard="registry_validity",
                        reason_code="STALE_REGISTRY_VERSION",
                        message=(
                            f"Proposal registry_version {proposal.registry_version!r} is stale "
                            f"compared to {registry.registry_version!r}."
                        ),
                        missing_requirements=["current_registry_version"],
                    )
                )
                return results

        # 5. Exact identity, hash, decision, and freshness validation.
        try:
            validate_approval_for_proposal(proposal, approval, reference_time=now)
        except ExpiredApprovalError as exc:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="approval_freshness",
                    reason_code="APPROVAL_EXPIRED",
                    message=exc.message,
                    missing_requirements=["fresh_human_approval"],
                )
            )
            return results
        except InvalidApprovalError as exc:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="approval_validity",
                    reason_code="INVALID_APPROVAL_BINDING",
                    message=exc.message,
                    missing_requirements=["matching_proposal_approval"],
                )
            )
            return results

        # 6. Feature state observation and expected-state drift validation.
        if feature_state is None:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="feature_state_freshness",
                    reason_code="MISSING_FEATURE_STATE",
                    message="Current observed FeatureState is required before applying changes.",
                    missing_requirements=["observed_feature_state"],
                )
            )
            return results
        if feature_state.observation_status != FeatureObservationStatus.OBSERVED:
            results.append(
                GuardResult(
                    allowed=False,
                    guard="feature_state_freshness",
                    reason_code="UNKNOWN_FEATURE_STATE",
                    message="Feature state is unknown or unavailable; cannot authorize write.",
                    missing_requirements=["observed_feature_state"],
                )
            )
            return results
        if (
            feature_state.environment != proposal.environment
            or feature_state.feature_name != proposal.flag_name
        ):
            results.append(
                GuardResult(
                    allowed=False,
                    guard="feature_state_freshness",
                    reason_code="FEATURE_STATE_TARGET_MISMATCH",
                    message="Observed FeatureState does not match proposal environment/feature.",
                    missing_requirements=["matching_feature_state"],
                )
            )
            return results
        if (
            proposal.expected_current_enabled is not None
            and feature_state.enabled != proposal.expected_current_enabled
        ):
            results.append(
                GuardResult(
                    allowed=False,
                    guard="feature_state_freshness",
                    reason_code="FEATURE_STATE_DRIFT",
                    message=(
                        f"Feature state drifted: expected {proposal.expected_current_enabled}, "
                        f"observed {feature_state.enabled}. Fresh approval required."
                    ),
                    missing_requirements=["revalidated_proposal_and_approval"],
                )
            )
            return results

        results.append(
            GuardResult(
                allowed=True,
                guard="approval_validity",
                reason_code="APPROVAL_VERIFIED",
                message="Authenticated human approval verified against active proposal.",
            )
        )
        return results

    def validate_stage_approval(
        self,
        *,
        incident: IncidentAggregate,
        approval: ApprovalDecision | None,
        producer: ProducerContext,
        stage_id: str,
        consumed_approval_ids: set[str] | None = None,
    ) -> GuardResult:
        """Validate a stage-specific or rollback human approval decision."""
        now = self._clock.now()
        if not producer.authenticated or producer.actor_type != ActorType.HUMAN_OPERATOR:
            return GuardResult(
                allowed=False,
                guard="approval_validity",
                reason_code="UNAUTHENTICATED_OR_NON_HUMAN_APPROVER",
                message="Stage/rollback approval requires authenticated HUMAN_OPERATOR producer.",
                missing_requirements=["authenticated_human_operator"],
            )
        if approval is None:
            return GuardResult(
                allowed=False,
                guard="approval_validity",
                reason_code="MISSING_STAGE_APPROVAL",
                message=f"Approval decision missing for target {stage_id!r}.",
                missing_requirements=["stage_approval_decision"],
            )
        if approval.incident_id != incident.incident_id:
            return GuardResult(
                allowed=False,
                guard="approval_validity",
                reason_code="APPROVAL_INCIDENT_MISMATCH",
                message="Approval incident_id does not match current incident.",
                missing_requirements=["matching_incident_approval"],
            )
        if approval.decision != ApprovalStatus.APPROVED:
            return GuardResult(
                allowed=False,
                guard="approval_validity",
                reason_code="APPROVAL_NOT_APPROVED",
                message=f"Approval decision is {approval.decision.value!r}, not 'approved'.",
                missing_requirements=["approved_decision"],
            )
        if approval.expires_at <= now:
            return GuardResult(
                allowed=False,
                guard="approval_freshness",
                reason_code="APPROVAL_EXPIRED",
                message="Stage/rollback approval has expired.",
                missing_requirements=["fresh_stage_approval"],
            )
        if approval.decided_at > now:
            return GuardResult(
                allowed=False,
                guard="approval_freshness",
                reason_code="FUTURE_APPROVAL_TIMESTAMP",
                message="Approval timestamp is in the future.",
                missing_requirements=["valid_approval_timestamp"],
            )
        all_consumed = set(incident.consumed_approval_ids)
        if consumed_approval_ids:
            all_consumed.update(consumed_approval_ids)
        if approval.approval_id in all_consumed:
            return GuardResult(
                allowed=False,
                guard="approval_validity",
                reason_code="APPROVAL_ALREADY_CONSUMED",
                message="Approval cannot be reused across distinct rollout stages or actions.",
                missing_requirements=["fresh_stage_specific_approval"],
            )
        if stage_id and approval.proposal_id != stage_id:
            return GuardResult(
                allowed=False,
                guard="approval_validity",
                reason_code="STAGE_APPROVAL_TARGET_MISMATCH",
                message=(
                    f"Approval target {approval.proposal_id!r} does not match "
                    f"requested stage {stage_id!r}."
                ),
                missing_requirements=["matching_stage_approval"],
            )
        return GuardResult(
            allowed=True,
            guard="approval_validity",
            reason_code="STAGE_APPROVAL_VERIFIED",
            message=f"Stage/rollback approval {approval.approval_id!r} verified.",
        )
