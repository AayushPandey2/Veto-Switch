"""Immutable RollbackProposal construction with canonical hashing."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from shared.enums import (
    RollbackFeasibilityStatus,
    RollbackStrategyType,
)
from shared.identifiers import generate_prefixed_id
from shared.schemas import (
    BooleanRollbackAction,
    RollbackPolicyConfig,
    RollbackProposal,
    TargetingRollbackAction,
    VerifiedSafeState,
)
from shared.serialization import sha256_canonical

from remediation.recovery.models import (
    RollbackCandidateStrategy,
    RollbackContext,
    SafeStateResolutionResult,
    TriggerValidationResult,
)


def build_rollback_proposal(
    ctx: RollbackContext,
    trigger: TriggerValidationResult,
    safe_state: SafeStateResolutionResult,
    selected: RollbackCandidateStrategy,
    all_candidates: list[RollbackCandidateStrategy],
    *,
    policy: RollbackPolicyConfig | None = None,
) -> RollbackProposal:
    """Build an immutable, canonically hashed RollbackProposal."""
    active_policy = policy or RollbackPolicyConfig()
    proposal_id = generate_prefixed_id("rollback")

    cp = safe_state.selected_checkpoint
    safe_cp = cp if isinstance(cp, VerifiedSafeState) else None
    safe_known = safe_cp is not None
    last_safe_bool: bool | None = safe_cp.global_feature_state if safe_cp is not None else None
    last_safe_id: str | None = safe_cp.safe_state_id if safe_cp is not None else None

    current_enabled: bool | None = (
        ctx.current_observed_feature_state.enabled
        if ctx.current_observed_feature_state is not None
        else None
    )

    targeting_action: BooleanRollbackAction | TargetingRollbackAction | None = None
    proposed_state = False
    proposed_targeting_cfg: dict[str, Any] | None = None
    action_type = selected.action_type

    if (
        selected.strategy_type == RollbackStrategyType.RESTORE_VERIFIED_TARGETING
        and safe_cp is not None
    ):
        desired_exp = int(
            selected.intended_state_change.get(
                "desired_exposure", safe_cp.configured_exposure_percentage
            )
        )
        proposed_state = bool(safe_cp.global_feature_state)
        proposed_targeting_cfg = dict(
            safe_cp.targeting_configuration or {"exposure_percentage": desired_exp}
        )
        targeting_action = TargetingRollbackAction(
            target_feature=ctx.target_feature,
            environment=ctx.environment,
            expected_current_targeting_version=ctx.current_targeting_version,
            expected_current_configuration=dict(ctx.current_targeting_configuration or {}),
            desired_targeting_configuration=proposed_targeting_cfg,
            expected_current_exposure=ctx.current_observed_exposure,
            desired_exposure=desired_exp,
        )
    elif selected.strategy_type in (
        RollbackStrategyType.DISABLE_REPLACEMENT_FEATURE,
        RollbackStrategyType.RESTORE_VERIFIED_FALLBACK,
    ):
        proposed_state = False
        targeting_action = BooleanRollbackAction(
            action_type=action_type,
            target_feature=ctx.target_feature,
            environment=ctx.environment,
            expected_current_enabled=current_enabled,
            desired_enabled=False,
        )
    else:
        proposed_state = False

    limitations = list(
        dict.fromkeys(
            [
                *trigger.limitations,
                *safe_state.limitations,
                *selected.limitations,
                *(
                    ["Unknown last verified-safe state; manual review required."]
                    if not safe_known
                    else []
                ),
            ]
        )
    )

    manual_review_required = (
        not safe_known
        or selected.feasibility_status != RollbackFeasibilityStatus.ELIGIBLE_FOR_EXECUTION_PROPOSAL
        or active_policy.require_fresh_human_approval
    )

    idem_token = sha256_canonical(
        {
            "incident_id": ctx.incident_id,
            "proposal_id": proposal_id,
            "target_environment": ctx.environment,
            "target_feature": ctx.target_feature,
            "action_type": action_type.value,
            "proposed_state": proposed_state,
            "proposed_targeting_configuration": proposed_targeting_cfg,
        }
    )[:32]

    expires_at = ctx.evaluation_timestamp + timedelta(
        seconds=active_policy.proposal_expiration_seconds
    )

    return RollbackProposal(
        proposal_id=proposal_id,
        incident_id=ctx.incident_id,
        plan_id=ctx.plan_id,
        current_stage_id=ctx.current_stage_id,
        trigger_decision_id=(ctx.rollout_decision.decision_id if ctx.rollout_decision else None),
        target_environment=ctx.environment,
        target_feature=ctx.target_feature,
        provider_feature_id=ctx.provider_feature_id,
        deployment_identity=ctx.deployment_identity or (
            ctx.deployment_evidence.source_revision if ctx.deployment_evidence else None
        ),
        candidate_identity=ctx.active_candidate_identity,
        action_type=action_type,
        targeting_action=targeting_action,
        current_state=current_enabled,
        expected_targeting_version=ctx.current_targeting_version,
        last_verified_safe_state_known=safe_known,
        last_verified_safe_state=last_safe_bool,
        last_verified_safe_state_id=last_safe_id,
        proposed_state=proposed_state,
        proposed_targeting_configuration=proposed_targeting_cfg,
        triggering_evidence_ids=trigger.triggering_evidence_ids or ["ev_rollback_trigger"],
        supporting_evidence_ids=list(selected.supporting_evidence),
        rollback_rationale=trigger.rationale,
        alternative_strategies=[c.model_dump(mode="json") for c in all_candidates],
        safety_limitations=limitations,
        required_post_rollback_tests=list(selected.required_verification),
        policy_version=active_policy.policy_version,
        manual_review_required=manual_review_required,
        approval_required=True,
        execution_authorized=False,
        created_at=ctx.evaluation_timestamp,
        expires_at=expires_at,
        idempotency_token=idem_token,
    )
