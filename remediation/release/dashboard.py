"""Dashboard serializer and Phase 10 Rollback handoff builder."""

from __future__ import annotations

from typing import Any

from shared.enums import RollbackReasonCode, RolloutDecisionType
from shared.schemas import MetricSnapshot, RolloutDecision, RolloutPlan, VerificationResult

from remediation.policies import GuardrailCheckResult
from remediation.release.models import (
    FinalRecoveryAssessment,
    RollbackHandoffContext,
    StageActionProposal,
)


def build_phase10_rollback_handoff(
    *,
    plan: RolloutPlan,
    decision: RolloutDecision,
    observed_exposure: int | None = None,
    targeting_configuration: dict[str, Any] | None = None,
    targeting_version: str | None = None,
    security_regression_result: VerificationResult | None = None,
    candidate_identity: str | None = None,
    last_verified_successful_stage: str | None = None,
    last_verified_safe_state_reference: str | None = None,
) -> RollbackHandoffContext:
    """Build typed Phase 09 -> Phase 10 rollback recommendation handoff."""
    reasons: list[RollbackReasonCode] = []
    if (
        security_regression_result is not None
        and security_regression_result.vulnerability_reproduced is True
    ):
        reasons.append(RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED)
    elif decision.failed_guardrails:
        reasons.append(RollbackReasonCode.OPERATIONAL_GUARDRAIL_BREACH)

    return RollbackHandoffContext(
        incident_id=plan.incident_id,
        plan_id=plan.plan_id,
        current_stage_id=decision.current_stage_id,
        current_observed_exposure=observed_exposure,
        target_feature=plan.target_feature,
        environment=plan.environment,
        current_targeting_configuration=dict(targeting_configuration or {}),
        targeting_version=targeting_version,
        failed_guardrails=list(decision.failed_guardrails),
        security_regression_result=security_regression_result,
        deployment_revision=plan.target_implementation_revision,
        candidate_identity=candidate_identity,
        triggering_evidence_ids=list(decision.evidence_ids),
        last_verified_successful_stage=last_verified_successful_stage,
        last_verified_safe_state_reference=last_verified_safe_state_reference,
        reason_codes=reasons,
        limitations=[
            "Rollout decision recommends rollback review; "
            "execution requires Phase 10 proposal and fresh approval."
        ],
    )


def serialize_rollout_dashboard(
    *,
    plan: RolloutPlan,
    decision: RolloutDecision,
    telemetry: MetricSnapshot,
    baseline: MetricSnapshot | None = None,
    checks: list[GuardrailCheckResult] | None = None,
    next_proposal: StageActionProposal | None = None,
    final_assessment: FinalRecoveryAssessment | None = None,
    rollback_handoff: RollbackHandoffContext | None = None,
    observed_exposure: int | None = None,
    approval_status: str = "pending",
    execution_status: str = "not_executed",
    readback_status: str = "not_run",
) -> dict[str, Any]:
    """Produce a deterministic JSON-serializable dashboard payload for Phase 09."""
    base_err = baseline.error_rate if baseline else telemetry.baseline_error_rate
    base_p95 = (
        baseline.latency_ms.p95_ms
        if baseline and baseline.latency_ms
        else telemetry.baseline_p95_latency_ms
    )
    err_pp = (
        round(100.0 * (telemetry.error_rate - base_err), 4)
        if base_err is not None and telemetry.error_rate is not None
        else None
    )
    cur_p95 = telemetry.latency_ms.p95_ms if telemetry.latency_ms else None
    lat_pct = (
        round(100.0 * (cur_p95 - base_p95) / base_p95, 2)
        if base_p95 is not None and base_p95 > 0 and cur_p95 is not None
        else None
    )

    return {
        "plan_id": plan.plan_id,
        "incident_id": plan.incident_id,
        "target_feature": plan.target_feature,
        "target_environment": plan.environment,
        "observed_exposure_percentage": (
            observed_exposure
            if observed_exposure is not None
            else telemetry.observed_rollout_stage_percentage
        ),
        "approval_status": approval_status,
        "execution_status": execution_status,
        "readback_status": readback_status,
        "metrics": {
            "request_count": telemetry.request_count,
            "failed_request_count": telemetry.failed_request_count,
            "error_rate": telemetry.error_rate,
            "baseline_error_rate": base_err,
            "error_rate_increase_pp": err_pp,
            "p95_latency_ms": telemetry.latency_ms.p95_ms,
            "baseline_p95_latency_ms": base_p95,
            "p95_latency_increase_percent": lat_pct,
            "observation_window_seconds": telemetry.observation_window_seconds,
            "security_regression_passed": telemetry.security_regression_passed,
        },
        "guardrail_results": [c.model_dump(mode="json") for c in (checks or [])],
        "decision": {
            "type": decision.decision_type.value,
            "current_stage_id": decision.current_stage_id,
            "proposed_next_stage_id": decision.proposed_next_stage_id,
            "proposed_next_exposure_percentage": (
                next_proposal.requested_exposure if next_proposal else None
            ),
            "approval_required": decision.approval_required,
            "execution_authorized": False,
            "explanation": decision.explanation,
        },
        "next_proposed_stage": next_proposal.model_dump(mode="json") if next_proposal else None,
        "final_assessment": (
            final_assessment.model_dump(mode="json") if final_assessment else None
        ),
        "rollback_recommendation": (
            rollback_handoff.model_dump(mode="json")
            if rollback_handoff
            else (
                {"recommended": True, "failed_guardrails": decision.failed_guardrails}
                if decision.decision_type == RolloutDecisionType.ROLLBACK_PROPOSED
                else None
            )
        ),
        "evidence_ids": list(decision.evidence_ids),
        "limitations": (
            ["Synthetic telemetry; does not establish live production reliability."]
            if telemetry.provenance.value == "synthetic_telemetry"
            else []
        ),
    }
