"""Deterministic rollback strategy selection enforcing security precedence."""

from __future__ import annotations

from shared.enums import (
    RollbackFeasibilityStatus,
    RollbackStrategyType,
)
from shared.schemas import RollbackPolicyConfig

from remediation.recovery.models import (
    RollbackCandidateStrategy,
    SafeStateResolutionResult,
    TriggerValidationResult,
)

_PRIORITY_ORDER: dict[RollbackStrategyType, int] = {
    RollbackStrategyType.RESTORE_VERIFIED_TARGETING: 0,
    RollbackStrategyType.RESTORE_VERIFIED_FALLBACK: 1,
    RollbackStrategyType.DISABLE_REPLACEMENT_FEATURE: 2,
    RollbackStrategyType.HOLD_AND_RECONCILE: 3,
    RollbackStrategyType.MANUAL_EMERGENCY_MITIGATION: 4,
}


def select_rollback_strategy(
    candidates: list[RollbackCandidateStrategy],
    trigger: TriggerValidationResult,
    safe_state: SafeStateResolutionResult,
    *,
    policy: RollbackPolicyConfig | None = None,
) -> RollbackCandidateStrategy:
    """Select the safest supported strategy deterministically.

    Security prerequisites are hard gates; a numerical score never overrides
    legacy containment or security regression elimination.
    """
    _ = policy or RollbackPolicyConfig()

    # If trigger is missing evidence (hold), return Hold & Reconcile.
    if trigger.is_missing_evidence_hold or not trigger.valid:
        for c in candidates:
            if c.strategy_type == RollbackStrategyType.HOLD_AND_RECONCILE:
                return c

    # Executable candidates that pass all security and capability gates.
    executable = [
        c
        for c in candidates
        if c.feasibility_status == RollbackFeasibilityStatus.ELIGIBLE_FOR_EXECUTION_PROPOSAL
        and c.preserves_legacy_containment
        and (not trigger.is_security_regression or c.eliminates_vulnerable_exposure)
    ]

    if executable:
        # On confirmed security regression, prefer verified fallback / full disable.
        if trigger.is_security_regression:
            sec_order = {
                RollbackStrategyType.RESTORE_VERIFIED_FALLBACK: 0,
                RollbackStrategyType.DISABLE_REPLACEMENT_FEATURE: 1,
            }
            executable.sort(key=lambda c: sec_order.get(c.strategy_type, 99))
            return executable[0]

        executable.sort(key=lambda c: _PRIORITY_ORDER.get(c.strategy_type, 99))
        return executable[0]

    # No executable strategy: prefer review/hold/manual.
    reviewable = [
        c
        for c in candidates
        if c.feasibility_status
        in (
            RollbackFeasibilityStatus.ELIGIBLE_FOR_REVIEW,
            RollbackFeasibilityStatus.MANUAL_REVIEW_ONLY,
        )
        and c.preserves_legacy_containment
    ]
    if reviewable:
        # Prefer HOLD_AND_RECONCILE or MANUAL_EMERGENCY_MITIGATION when safe state is unknown.
        if not safe_state.known:
            for c in reviewable:
                if c.strategy_type == RollbackStrategyType.HOLD_AND_RECONCILE:
                    return c
        reviewable.sort(key=lambda c: _PRIORITY_ORDER.get(c.strategy_type, 99))
        return reviewable[0]

    for c in candidates:
        if c.strategy_type == RollbackStrategyType.MANUAL_EMERGENCY_MITIGATION:
            return c
    return candidates[0]
