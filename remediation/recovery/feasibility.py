"""Deterministic feasibility gates for candidate rollback strategies."""

from __future__ import annotations

from shared.enums import (
    DeploymentStatus,
    FeatureObservationStatus,
    RollbackActionType,
    RollbackFeasibilityStatus,
    RollbackReasonCode,
    RollbackStrategyType,
)

from remediation.recovery.models import (
    RollbackCandidateStrategy,
    RollbackContext,
    SafeStateResolutionResult,
    TriggerValidationResult,
)


def evaluate_strategy_feasibility(
    strategy: RollbackCandidateStrategy,
    ctx: RollbackContext,
    trigger: TriggerValidationResult,
    safe_state: SafeStateResolutionResult,
) -> RollbackCandidateStrategy:
    """Evaluate hard feasibility prerequisites without allowing scores to override safety."""
    if strategy.strategy_type in (
        RollbackStrategyType.HOLD_AND_RECONCILE,
        RollbackStrategyType.MANUAL_EMERGENCY_MITIGATION,
    ):
        return strategy

    missing = list(strategy.missing_prerequisites)
    reasons = list(strategy.reason_codes)
    limitations = list(strategy.limitations)

    if not trigger.valid:
        missing.append("valid_rollback_trigger")
        if RollbackReasonCode.TRIGGER_EVIDENCE_MISSING not in reasons:
            reasons.append(RollbackReasonCode.TRIGGER_EVIDENCE_MISSING)

    # Current observed state check
    if (
        ctx.current_observed_feature_state is None
        or ctx.current_observed_feature_state.observation_status
        != FeatureObservationStatus.OBSERVED
    ):
        missing.append("observed_current_feature_state")
        if RollbackReasonCode.CURRENT_STATE_UNKNOWN not in reasons:
            reasons.append(RollbackReasonCode.CURRENT_STATE_UNKNOWN)

    # Deployment check
    if ctx.deployment_evidence is not None and (
        ctx.deployment_evidence.deployment_status != DeploymentStatus.OBSERVED
        or ctx.deployment_evidence.environment != ctx.environment
    ):
        missing.append("compatible_observed_deployment")
        if RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH not in reasons:
            reasons.append(RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH)

    # Legacy vulnerable path protection (non-negotiable)
    if not strategy.preserves_legacy_containment:
        missing.append("legacy_vulnerable_path_contained")
        if RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED not in reasons:
            reasons.append(RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED)

    # Security regression must not leave partial vulnerable cohort
    if trigger.is_security_regression and not strategy.eliminates_vulnerable_exposure:
        missing.append("eliminates_vulnerable_exposure")
        if RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED not in reasons:
            reasons.append(RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED)

    # Fallback verification for full disable
    if (
        strategy.strategy_type == RollbackStrategyType.DISABLE_REPLACEMENT_FEATURE
        and not ctx.executor_capabilities.fallback_verified
    ):
        missing.append("verified_safe_fallback")
        if RollbackReasonCode.FALLBACK_NOT_VERIFIED not in reasons:
            reasons.append(RollbackReasonCode.FALLBACK_NOT_VERIFIED)
        limitations.append("Fallback behavior has not been independently verified.")

    # Executor capability check for targeting vs boolean
    if (
        strategy.action_type == RollbackActionType.TARGETING_CONFIGURATION
        and not ctx.executor_capabilities.supports_targeting
    ):
        missing.append("executor_targeting_support")
        if RollbackReasonCode.TARGETING_EXECUTOR_UNAVAILABLE not in reasons:
            reasons.append(RollbackReasonCode.TARGETING_EXECUTOR_UNAVAILABLE)
        if RollbackReasonCode.ROLLBACK_ACTION_UNSUPPORTED not in reasons:
            reasons.append(RollbackReasonCode.ROLLBACK_ACTION_UNSUPPORTED)
        limitations.append(
            "External executor supports Boolean changes only; "
            "targeting rollback is non-executable."
        )
        return strategy.model_copy(
            update={
                "feasibility_status": RollbackFeasibilityStatus.UNSUPPORTED,
                "missing_prerequisites": sorted(set(missing)),
                "reason_codes": reasons,
                "limitations": limitations,
            }
        )
    if (
        strategy.action_type
        in (
            RollbackActionType.BOOLEAN_STATE,
            RollbackActionType.SAFE_FALLBACK,
        )
        and not ctx.executor_capabilities.supports_boolean
    ):
        missing.append("executor_boolean_support")
        if RollbackReasonCode.ROLLBACK_ACTION_UNSUPPORTED not in reasons:
            reasons.append(RollbackReasonCode.ROLLBACK_ACTION_UNSUPPORTED)
        return strategy.model_copy(
            update={
                "feasibility_status": RollbackFeasibilityStatus.UNSUPPORTED,
                "missing_prerequisites": sorted(set(missing)),
                "reason_codes": reasons,
                "limitations": limitations,
            }
        )

    if missing:
        status = (
            RollbackFeasibilityStatus.UNSUPPORTED
            if (
                not strategy.preserves_legacy_containment
                or (trigger.is_security_regression and not strategy.eliminates_vulnerable_exposure)
            )
            else RollbackFeasibilityStatus.ELIGIBLE_FOR_REVIEW
        )
        return strategy.model_copy(
            update={
                "feasibility_status": status,
                "missing_prerequisites": sorted(set(missing)),
                "reason_codes": reasons,
                "limitations": limitations,
            }
        )

    return strategy.model_copy(
        update={
            "feasibility_status": RollbackFeasibilityStatus.ELIGIBLE_FOR_EXECUTION_PROPOSAL,
            "missing_prerequisites": [],
            "reason_codes": reasons,
            "limitations": limitations,
        }
    )
