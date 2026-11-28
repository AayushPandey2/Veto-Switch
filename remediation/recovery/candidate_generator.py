"""Bounded rollback candidate strategy generation (Strategies A-E)."""

from __future__ import annotations

from shared.enums import (
    CoverageStatus,
    FeatureObservationStatus,
    RollbackActionType,
    RollbackFeasibilityStatus,
    RollbackReasonCode,
    RollbackStrategyType,
)
from shared.schemas import RollbackPolicyConfig, VerifiedSafeState

from remediation.recovery.models import (
    RollbackCandidateStrategy,
    RollbackContext,
    SafeStateResolutionResult,
    TriggerValidationResult,
)


def _legacy_exposure_risk(
    ctx: RollbackContext, policy: RollbackPolicyConfig
) -> tuple[bool, list[str]]:
    """Return (legacy_exposed, reasons) if disabling replacement could expose vulnerable legacy."""
    reasons: list[str] = []
    if ctx.current_legacy_feature_state is None:
        reasons.append(
            "Current state of known vulnerable legacy feature(s) is unobserved; "
            "cannot verify containment."
        )
        return True, reasons
    if ctx.current_legacy_feature_state.observation_status != FeatureObservationStatus.OBSERVED:
        reasons.append("Legacy feature state observation_status is not OBSERVED.")
        return True, reasons
    if ctx.current_legacy_feature_state.enabled:
        reasons.append(
            f"Known vulnerable legacy feature "
            f"{ctx.current_legacy_feature_state.feature_name!r} is enabled."
        )
        return True, reasons
    if ctx.legacy_segment_overrides:
        reasons.append("Active segment overrides exist for known vulnerable legacy implementation.")
        return True, reasons
    for cov in ctx.coverage_findings:
        if cov.coverage_status in (CoverageStatus.UNPROTECTED, CoverageStatus.PARTIALLY_PROTECTED):
            reasons.append(
                f"Coverage finding {cov.coverage_finding_id} reports "
                f"{cov.coverage_status.value} route {cov.route!r}."
            )
            return True, reasons
    return False, reasons


def generate_candidate_strategies(
    ctx: RollbackContext,
    trigger: TriggerValidationResult,
    safe_state: SafeStateResolutionResult,
    *,
    policy: RollbackPolicyConfig | None = None,
) -> list[RollbackCandidateStrategy]:
    """Generate bounded candidate rollback strategies A-E without mutating state."""
    active_policy = policy or RollbackPolicyConfig()
    candidates: list[RollbackCandidateStrategy] = []
    legacy_risk, legacy_reasons = _legacy_exposure_risk(ctx, active_policy)

    # Strategy A — Restore a verified earlier targeting configuration
    cp = safe_state.selected_checkpoint
    if isinstance(cp, VerifiedSafeState):
        if (
            trigger.is_security_regression
            and not active_policy.allow_partial_exposure_on_security_regression
        ):
            candidates.append(
                RollbackCandidateStrategy(
                    strategy_id="strat_a_restore_verified_targeting",
                    strategy_type=RollbackStrategyType.RESTORE_VERIFIED_TARGETING,
                    action_type=RollbackActionType.TARGETING_CONFIGURATION,
                    intended_state_change={
                        "target_feature": ctx.target_feature,
                        "desired_exposure": cp.configured_exposure_percentage,
                        "desired_enabled": cp.global_feature_state,
                    },
                    current_state_precondition={
                        "expected_exposure": ctx.current_observed_exposure,
                        "expected_targeting_version": ctx.current_targeting_version,
                    },
                    expected_security_effect=(
                        "Insufficient: partial exposure leaves cohort exposed to "
                        "confirmed security regression."
                    ),
                    expected_operational_effect=(
                        f"Reduces exposure to {cp.configured_exposure_percentage}%."
                    ),
                    supporting_evidence=[cp.safe_state_id, *cp.security_verification_ids],
                    feasibility_status=RollbackFeasibilityStatus.UNSUPPORTED,
                    missing_prerequisites=["full_containment_required_for_security_regression"],
                    limitations=[
                        "Partial exposure reduction cannot resolve a confirmed security regression."
                    ],
                    reason_codes=[RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED],
                    preserves_legacy_containment=not legacy_risk,
                    eliminates_vulnerable_exposure=False,
                )
            )
        else:
            candidates.append(
                RollbackCandidateStrategy(
                    strategy_id="strat_a_restore_verified_targeting",
                    strategy_type=RollbackStrategyType.RESTORE_VERIFIED_TARGETING,
                    action_type=RollbackActionType.TARGETING_CONFIGURATION,
                    intended_state_change={
                        "target_feature": ctx.target_feature,
                        "desired_exposure": cp.configured_exposure_percentage,
                        "desired_enabled": cp.global_feature_state,
                        "desired_targeting_configuration": cp.targeting_configuration,
                    },
                    current_state_precondition={
                        "expected_exposure": ctx.current_observed_exposure,
                        "expected_targeting_version": ctx.current_targeting_version,
                    },
                    expected_security_effect=(
                        "Preserves verified security containment at prior stage."
                    ),
                    expected_operational_effect=(
                        f"Restores exposure from {ctx.current_observed_exposure}% "
                        f"to {cp.configured_exposure_percentage}%."
                    ),
                    supporting_evidence=[cp.safe_state_id, *cp.telemetry_snapshot_ids],
                    feasibility_status=RollbackFeasibilityStatus.ANALYTICALLY_POSSIBLE,
                    required_verification=[
                        "readback_reconciliation",
                        "security_regression",
                        "functional_smoke",
                    ],
                    preserves_legacy_containment=not legacy_risk,
                    eliminates_vulnerable_exposure=True,
                )
            )

    # Strategy B — Disable the replacement feature
    candidates.append(
        RollbackCandidateStrategy(
            strategy_id="strat_b_disable_replacement",
            strategy_type=RollbackStrategyType.DISABLE_REPLACEMENT_FEATURE,
            action_type=RollbackActionType.BOOLEAN_STATE,
            intended_state_change={
                "target_feature": ctx.target_feature,
                "desired_enabled": False,
                "desired_exposure": 0,
            },
            current_state_precondition={
                "expected_current_enabled": (
                    ctx.current_observed_feature_state.enabled
                    if ctx.current_observed_feature_state is not None
                    else None
                ),
            },
            expected_security_effect=(
                "Blocks vulnerable replacement implementation; "
                "safe only if legacy remains disabled."
                if not legacy_risk
                else "UNSAFE: Disabling replacement risks exposing vulnerable legacy path."
            ),
            expected_operational_effect=(
                "Disables replacement search feature; routes to declared fallback."
            ),
            fallback_requirements=(
                [f"declared_fallback:{ctx.executor_capabilities.declared_fallback_behavior}"]
                if ctx.executor_capabilities.declared_fallback_behavior
                else ["verified_safe_fallback_required"]
            ),
            supporting_evidence=list(trigger.triggering_evidence_ids),
            feasibility_status=RollbackFeasibilityStatus.ANALYTICALLY_POSSIBLE,
            missing_prerequisites=legacy_reasons if legacy_risk else [],
            required_verification=[
                "readback_reconciliation",
                "security_regression",
                "alternate_route_coverage",
                "functional_smoke",
            ],
            limitations=legacy_reasons,
            reason_codes=(
                [RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED] if legacy_risk else []
            ),
            preserves_legacy_containment=not legacy_risk,
            eliminates_vulnerable_exposure=not legacy_risk,
        )
    )

    # Strategy C — Restore an independently verified safe fallback
    if (
        ctx.executor_capabilities.fallback_verified
        and ctx.executor_capabilities.declared_fallback_behavior
    ):
        candidates.append(
            RollbackCandidateStrategy(
                strategy_id="strat_c_restore_verified_fallback",
                strategy_type=RollbackStrategyType.RESTORE_VERIFIED_FALLBACK,
                action_type=RollbackActionType.SAFE_FALLBACK,
                intended_state_change={
                    "target_feature": ctx.target_feature,
                    "desired_enabled": False,
                    "fallback_behavior": ctx.executor_capabilities.declared_fallback_behavior,
                    "app_target": ctx.executor_capabilities.app_target,
                },
                current_state_precondition={
                    "expected_current_enabled": (
                        ctx.current_observed_feature_state.enabled
                        if ctx.current_observed_feature_state is not None
                        else None
                    ),
                },
                expected_security_effect="Routes traffic to independently verified safe fallback.",
                expected_operational_effect=(
                    f"Activates declared safe fallback "
                    f"({ctx.executor_capabilities.declared_fallback_behavior})."
                ),
                supporting_evidence=(
                    [ctx.executor_capabilities.fallback_verification_id]
                    if ctx.executor_capabilities.fallback_verification_id
                    else []
                ),
                feasibility_status=RollbackFeasibilityStatus.ANALYTICALLY_POSSIBLE,
                required_verification=[
                    "readback_reconciliation",
                    "security_regression",
                    "functional_smoke",
                ],
                preserves_legacy_containment=not legacy_risk,
                eliminates_vulnerable_exposure=not legacy_risk,
            )
        )

    # Strategy D — Hold and reconcile uncertainty
    candidates.append(
        RollbackCandidateStrategy(
            strategy_id="strat_d_hold_and_reconcile",
            strategy_type=RollbackStrategyType.HOLD_AND_RECONCILE,
            action_type=RollbackActionType.HOLD_STATE,
            intended_state_change={"action": "hold_no_mutation"},
            expected_security_effect=(
                "No mutation performed; preserves current state while reconciling."
            ),
            expected_operational_effect=(
                "Zero additional operational disruption; rollout remains paused."
            ),
            supporting_evidence=list(trigger.triggering_evidence_ids),
            feasibility_status=RollbackFeasibilityStatus.MANUAL_REVIEW_ONLY,
            required_verification=["state_reconciliation"],
            limitations=["Holding is not an executed rollback."],
            reason_codes=[RollbackReasonCode.MANUAL_REVIEW_REQUIRED],
            preserves_legacy_containment=not legacy_risk,
            eliminates_vulnerable_exposure=False,
        )
    )

    # Strategy E — Manual emergency mitigation
    candidates.append(
        RollbackCandidateStrategy(
            strategy_id="strat_e_manual_emergency",
            strategy_type=RollbackStrategyType.MANUAL_EMERGENCY_MITIGATION,
            action_type=RollbackActionType.MANUAL_EMERGENCY,
            intended_state_change={"action": "manual_operator_mitigation"},
            expected_security_effect=(
                "Operator-executed emergency mitigation outside automated executor."
            ),
            expected_operational_effect="Requires direct human incident-commander intervention.",
            supporting_evidence=list(trigger.triggering_evidence_ids),
            feasibility_status=RollbackFeasibilityStatus.MANUAL_REVIEW_ONLY,
            required_verification=["manual_verification", "security_regression"],
            limitations=["Automated proposal mechanism cannot execute this action."],
            reason_codes=[RollbackReasonCode.MANUAL_REVIEW_REQUIRED],
            preserves_legacy_containment=True,
            eliminates_vulnerable_exposure=False,
        )
    )

    return candidates
