"""Deterministic rollback trigger validation."""

from __future__ import annotations

from shared.enums import (
    RollbackReasonCode,
    RollbackTriggerCategory,
    RolloutDecisionType,
)

from remediation.recovery.models import RollbackContext, TriggerValidationResult


def validate_rollback_trigger(ctx: RollbackContext) -> TriggerValidationResult:
    """Validate and classify the rollback trigger from Phase 09 or operator input.

    Distinguishes confirmed security regression, operational degradation, missing
    evidence (hold), and manual operator requests without inventing failures.
    """
    decision = ctx.rollout_decision
    telemetry = ctx.triggering_telemetry
    sec_res = ctx.security_regression_result
    evidence_ids = list(ctx.evidence_references)

    if decision is not None:
        if decision.incident_id != ctx.incident_id:
            return TriggerValidationResult(
                valid=False,
                reason_codes=[RollbackReasonCode.TRIGGER_EVIDENCE_MISSING],
                rationale="RolloutDecision belongs to a different incident.",
                limitations=["Cross-incident RolloutDecision rejected."],
            )
        for eid in decision.evidence_ids:
            if eid not in evidence_ids:
                evidence_ids.append(eid)

    if telemetry is not None:
        if telemetry.incident_id != ctx.incident_id:
            return TriggerValidationResult(
                valid=False,
                reason_codes=[RollbackReasonCode.TRIGGER_EVIDENCE_MISSING],
                rationale="MetricSnapshot belongs to a different incident.",
                limitations=["Cross-incident MetricSnapshot rejected."],
            )
        for eid in telemetry.evidence_ids:
            if eid not in evidence_ids:
                evidence_ids.append(eid)

    # 1. Confirmed security regression takes highest precedence.
    if (sec_res is not None and sec_res.vulnerability_reproduced is True) or (
        telemetry is not None and telemetry.security_regression_passed is False
    ):
        if sec_res is not None:
            for aid in sec_res.artifact_ids:
                if aid not in evidence_ids:
                    evidence_ids.append(aid)
        return TriggerValidationResult(
            valid=True,
            trigger_category=RollbackTriggerCategory.SECURITY_REGRESSION,
            is_security_regression=True,
            triggering_evidence_ids=evidence_ids or ["ev_security_regression"],
            failed_guardrails=list(
                ctx.failed_guardrails or (decision.failed_guardrails if decision else [])
            ),
            reason_codes=[RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED],
            rationale=(
                "Confirmed security regression detected on active replacement implementation."
            ),
        )

    # 2. Missing evidence / unknown security status -> hold, never fabricate failure.
    if decision is not None and decision.missing_evidence and not decision.failed_guardrails:
        return TriggerValidationResult(
            valid=False,
            is_missing_evidence_hold=True,
            triggering_evidence_ids=evidence_ids,
            reason_codes=[RollbackReasonCode.TRIGGER_EVIDENCE_MISSING],
            rationale=(
                "RolloutDecision indicates missing evidence; hold rather than fabricating failure."
            ),
            limitations=[
                "Missing telemetry or verification evidence requires hold/reconciliation."
            ],
        )

    # 3. Operational guardrail breach from RolloutDecision or telemetry.
    failed_guardrails = list(ctx.failed_guardrails)
    if decision is not None:
        for fg in decision.failed_guardrails:
            if fg not in failed_guardrails:
                failed_guardrails.append(fg)

    if (
        decision is not None
        and decision.decision_type == RolloutDecisionType.ROLLBACK_PROPOSED
        and failed_guardrails
    ) or failed_guardrails:
        category = RollbackTriggerCategory.ABSOLUTE_ERROR_RATE_BREACH
        if any("latency" in g.lower() for g in failed_guardrails):
            category = RollbackTriggerCategory.LATENCY_DEGRADATION
        elif any("baseline" in g.lower() for g in failed_guardrails):
            category = RollbackTriggerCategory.BASELINE_RELATIVE_ERROR_BREACH
        elif any("functional" in g.lower() for g in failed_guardrails):
            category = RollbackTriggerCategory.FUNCTIONAL_REGRESSION
        return TriggerValidationResult(
            valid=True,
            trigger_category=category,
            is_operational_degradation=True,
            triggering_evidence_ids=evidence_ids or ["ev_guardrail_breach"],
            failed_guardrails=failed_guardrails,
            reason_codes=[RollbackReasonCode.OPERATIONAL_GUARDRAIL_BREACH],
            rationale=f"Operational guardrail breach confirmed: {', '.join(failed_guardrails)}.",
        )

    # 4. Manual operator request initiates analysis without establishing safe target.
    if ctx.manual_operator_request:
        return TriggerValidationResult(
            valid=True,
            trigger_category=RollbackTriggerCategory.MANUAL_OPERATOR_REQUEST,
            triggering_evidence_ids=evidence_ids or ["ev_manual_operator_request"],
            reason_codes=[RollbackReasonCode.MANUAL_REVIEW_REQUIRED],
            rationale=ctx.manual_request_reason or "Manual operator rollback analysis requested.",
            limitations=[
                "Manual operator request does not establish safe state or authorize execution."
            ],
        )

    return TriggerValidationResult(
        valid=False,
        triggering_evidence_ids=evidence_ids,
        reason_codes=[RollbackReasonCode.TRIGGER_EVIDENCE_MISSING],
        rationale="No valid guardrail breach, security regression, or operator trigger found.",
        limitations=["Missing triggering evidence for rollback."],
    )
