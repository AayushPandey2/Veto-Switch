"""Final 100% stage recovery completion assessment."""

from __future__ import annotations

from agent_core.context import RolloutStageRecord
from shared.enums import (
    FeatureObservationStatus,
    RolloutDecisionType,
    TestExecutionStatus,
)
from shared.schemas import (
    FeatureState,
    RolloutDecision,
    RolloutPlan,
    VerificationResult,
)

from remediation.release.models import FinalRecoveryAssessment


def assess_final_stage_completion(
    *,
    plan: RolloutPlan,
    stage_records: list[RolloutStageRecord],
    final_decision: RolloutDecision | None,
    final_security_verification: VerificationResult | None,
    final_functional_verification: VerificationResult | None = None,
    legacy_feature_state: FeatureState | None = None,
    unresolved_rollback: bool = False,
) -> FinalRecoveryAssessment:
    """Assess whether the 100% stage satisfies all recovery completion invariants."""
    missing: list[str] = []

    if unresolved_rollback:
        missing.append("no_unresolved_rollback")

    by_id = {r.stage_id: r for r in stage_records}
    all_completed = True
    for stage in plan.stages:
        rec = by_id.get(stage.stage_id)
        if (
            rec is None
            or rec.status not in ("observed", "completed")
            or rec.approval_id is None
            or rec.operation_receipt_id is None
        ):
            all_completed = False
            missing.append(f"completed_authorized_stage:{stage.stage_id}")

    if (
        final_decision is None
        or final_decision.failed_guardrails
        or final_decision.missing_evidence
    ):
        missing.append("passing_final_guardrail_decision")
    elif final_decision.decision_type == RolloutDecisionType.ROLLBACK_PROPOSED:
        missing.append("no_rollback_recommended")

    sec_ok = (
        final_security_verification is not None
        and final_security_verification.execution_status == TestExecutionStatus.TEST_PASSED
        and final_security_verification.passed is True
        and final_security_verification.vulnerability_reproduced is not True
    )
    if not sec_ok:
        missing.append("final_security_verification")

    func_ok = (
        final_functional_verification is None
        or (
            final_functional_verification.execution_status == TestExecutionStatus.TEST_PASSED
            and final_functional_verification.passed is True
        )
    )
    if not func_ok:
        missing.append("final_functional_verification")

    legacy_ok = True
    if legacy_feature_state is not None and (
        legacy_feature_state.observation_status != FeatureObservationStatus.OBSERVED
        or legacy_feature_state.enabled
    ):
        legacy_ok = False
        missing.append("legacy_vulnerable_feature_contained")

    ready = len(missing) == 0 and all_completed and sec_ok and func_ok and legacy_ok
    return FinalRecoveryAssessment(
        incident_id=plan.incident_id,
        plan_id=plan.plan_id,
        ready_for_recovered=ready,
        all_stages_completed=all_completed,
        final_security_passed=sec_ok,
        final_functional_passed=func_ok,
        legacy_contained=legacy_ok,
        missing_requirements=missing,
        reason=(
            "All progressive stages, approvals, receipts, and final verifications passed."
            if ready
            else f"Recovery completion blocked: {', '.join(missing)}."
        ),
    )
