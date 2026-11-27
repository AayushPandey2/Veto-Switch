"""Deterministic rollout and recovery policy evaluation (Phase 09)."""

from __future__ import annotations

import math
from datetime import datetime

from pydantic import Field
from shared.config import load_rollout_policy
from shared.enums import (
    EvidenceProvenance,
    RolloutDecisionType,
)
from shared.identifiers import utc_now
from shared.schemas import (
    KillswitchModel,
    MetricSnapshot,
    RolloutDecision,
    RolloutGuardrailConfig,
    RolloutPlan,
    RolloutPolicyConfig,
    RolloutStage,
)

_METRIC_TOLERANCE = 0.015


class GuardrailCheckResult(KillswitchModel):
    """Structured result for a single deterministic rollout guardrail check."""

    guardrail_id: str = Field(min_length=1)
    status: str = Field(min_length=1)  # passed | failed | missing | invalid | not_applicable
    observed_value: float | int | bool | str | None = None
    threshold: float | int | bool | str | None = None
    comparison_operator: str = "<="
    unit: str = "unitless"
    baseline_reference: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    reason_code: str = Field(min_length=1)
    explanation: str = Field(min_length=1)


def wilson_confidence_interval(
    successes: int,
    total: int,
    *,
    z: float = 1.96,
) -> tuple[float, float]:
    """Compute Wilson score confidence interval for observed proportion.

    Note: Synthetic fixture counts do not represent independent production users.
    """
    if total <= 0:
        return (0.0, 1.0)
    p = max(0.0, min(1.0, successes / total))
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    margin = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total)) / denom
    return (max(0.0, round(center - margin, 6)), min(1.0, round(center + margin, 6)))


def evaluate_stage_guardrails(
    *,
    plan: RolloutPlan,
    stage: RolloutStage,
    telemetry: MetricSnapshot,
    baseline: MetricSnapshot | None = None,
    policy: RolloutPolicyConfig | None = None,
    observed_exposure: int | None = None,
    expected_revision: str | None = None,
    observed_revision: str | None = None,
    live_mode: bool = False,
    evaluation_time: datetime | None = None,
    max_telemetry_age_seconds: int = 3600,
) -> tuple[list[GuardrailCheckResult], RolloutDecision]:
    """Evaluate all deterministic release health guardrails without LLM calls."""
    active_policy = policy or load_rollout_policy()
    guardrails: RolloutGuardrailConfig = stage.guardrails or active_policy.guardrails
    now = evaluation_time or utc_now()
    checks: list[GuardrailCheckResult] = []
    evidence_ids = list(
        dict.fromkeys([*telemetry.evidence_ids, *(baseline.evidence_ids if baseline else [])])
    )

    # 1. Live mode vs synthetic telemetry separation
    if live_mode and telemetry.provenance == EvidenceProvenance.SYNTHETIC_TELEMETRY:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="telemetry_provenance",
                status="invalid",
                observed_value=telemetry.provenance.value,
                threshold="actual_observed",
                comparison_operator="==",
                unit="provenance",
                evidence_ids=list(telemetry.evidence_ids),
                reason_code="SYNTHETIC_TELEMETRY_IN_LIVE_MODE",
                explanation="Synthetic telemetry cannot authorize live rollout progression.",
            )
        )

    # 2. Deployment revision consistency
    if (
        expected_revision is not None
        and observed_revision is not None
        and expected_revision != observed_revision
    ):
        checks.append(
            GuardrailCheckResult(
                guardrail_id="deployment_revision_consistency",
                status="failed",
                observed_value=observed_revision,
                threshold=expected_revision,
                comparison_operator="==",
                unit="revision",
                reason_code="DEPLOYMENT_REVISION_MISMATCH",
                explanation=(
                    f"Observed revision {observed_revision!r} != expected {expected_revision!r}."
                ),
            )
        )
    else:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="deployment_revision_consistency",
                status="passed",
                observed_value=observed_revision or expected_revision,
                threshold=expected_revision,
                comparison_operator="==",
                unit="revision",
                reason_code="REVISION_MATCHED",
                explanation="Deployment revision matches plan target.",
            )
        )

    # 3. Stage readback consistency
    effective_exposure = (
        observed_exposure
        if observed_exposure is not None
        else telemetry.observed_rollout_stage_percentage
    )
    if effective_exposure is None:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="stage_readback_consistency",
                status="missing",
                observed_value=None,
                threshold=stage.exposure_percentage,
                comparison_operator="==",
                unit="percent",
                reason_code="MISSING_OBSERVED_EXPOSURE",
                explanation="Observed rollout stage exposure is missing.",
            )
        )
    elif effective_exposure != stage.exposure_percentage:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="stage_readback_consistency",
                status="missing",
                observed_value=effective_exposure,
                threshold=stage.exposure_percentage,
                comparison_operator="==",
                unit="percent",
                reason_code="OBSERVED_EXPOSURE_MISMATCH",
                explanation=(
                    f"Observed exposure {effective_exposure}% != "
                    f"approved stage {stage.exposure_percentage}%."
                ),
            )
        )
    else:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="stage_readback_consistency",
                status="passed",
                observed_value=effective_exposure,
                threshold=stage.exposure_percentage,
                comparison_operator="==",
                unit="percent",
                reason_code="EXPOSURE_MATCHED",
                explanation=f"Observed exposure matches {stage.exposure_percentage}%.",
            )
        )

    # 4. Telemetry freshness
    age_s = (now - telemetry.observed_at).total_seconds()
    if age_s > max_telemetry_age_seconds:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="telemetry_freshness",
                status="missing",
                observed_value=round(age_s, 1),
                threshold=max_telemetry_age_seconds,
                comparison_operator="<=",
                unit="seconds",
                reason_code="STALE_TELEMETRY",
                explanation=(
                    f"Telemetry age {int(age_s)}s exceeds max {max_telemetry_age_seconds}s."
                ),
            )
        )
    else:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="telemetry_freshness",
                status="passed",
                observed_value=round(max(0.0, age_s), 1),
                threshold=max_telemetry_age_seconds,
                comparison_operator="<=",
                unit="seconds",
                reason_code="TELEMETRY_FRESH",
                explanation="Telemetry snapshot is within freshness window.",
            )
        )

    # 5. Telemetry metric consistency (error_rate vs failed/total)
    req_count = telemetry.request_count
    fail_count = telemetry.failed_request_count
    obs_err = telemetry.error_rate
    if (
        req_count is not None
        and fail_count is not None
        and obs_err is not None
        and req_count > 0
    ):
        expected_err = fail_count / req_count
        if abs(expected_err - obs_err) > _METRIC_TOLERANCE:
            checks.append(
                GuardrailCheckResult(
                    guardrail_id="telemetry_consistency",
                    status="invalid",
                    observed_value=obs_err,
                    threshold=round(expected_err, 4),
                    comparison_operator="==",
                    unit="ratio",
                    reason_code="CONTRADICTORY_METRICS",
                    explanation=(
                        "Reported error_rate disagrees with failed_request_count / request_count."
                    ),
                )
            )

    # 6. Minimum request count
    min_req = max(stage.minimum_request_count, active_policy.minimum_request_count)
    req_ok = req_count is not None and req_count >= min_req
    checks.append(
        GuardrailCheckResult(
            guardrail_id="minimum_request_count",
            status="passed" if req_ok else "missing",
            observed_value=req_count,
            threshold=min_req,
            comparison_operator=">=",
            unit="requests",
            evidence_ids=list(telemetry.evidence_ids),
            reason_code="SUFFICIENT_REQUESTS" if req_ok else "INSUFFICIENT_REQUESTS",
            explanation=f"Observed {req_count} requests (minimum {min_req}).",
        )
    )

    # 7. Minimum observation window
    min_win = max(
        stage.minimum_observation_window_seconds,
        active_policy.minimum_observation_window_seconds,
    )
    checks.append(
        GuardrailCheckResult(
            guardrail_id="minimum_observation_window",
            status="passed" if telemetry.observation_window_seconds >= min_win else "missing",
            observed_value=telemetry.observation_window_seconds,
            threshold=min_win,
            comparison_operator=">=",
            unit="seconds",
            evidence_ids=list(telemetry.evidence_ids),
            reason_code=(
                "SUFFICIENT_WINDOW"
                if telemetry.observation_window_seconds >= min_win
                else "INSUFFICIENT_WINDOW"
            ),
            explanation=(
                f"Observed {telemetry.observation_window_seconds}s window (minimum {min_win}s)."
            ),
        )
    )

    # 8. Security regression (hard guardrail)
    if telemetry.security_regression_passed is True:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="security_regression",
                status="passed",
                observed_value=True,
                threshold=True,
                comparison_operator="==",
                unit="boolean",
                evidence_ids=list(telemetry.evidence_ids),
                reason_code="SECURITY_REGRESSION_PASSED",
                explanation="Stage security regression check passed.",
            )
        )
    elif telemetry.security_regression_passed is False:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="security_regression",
                status="failed",
                observed_value=False,
                threshold=True,
                comparison_operator="==",
                unit="boolean",
                evidence_ids=list(telemetry.evidence_ids),
                reason_code="SECURITY_REGRESSION_FAILED",
                explanation="Confirmed security regression failure during rollout stage.",
            )
        )
    else:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="security_regression",
                status="missing",
                observed_value=None,
                threshold=True,
                comparison_operator="==",
                unit="boolean",
                evidence_ids=list(telemetry.evidence_ids),
                reason_code="SECURITY_RESULT_UNKNOWN",
                explanation="Security regression status is unknown/not run; hold required.",
            )
        )

    # 9. Absolute error rate (only meaningful when sample > 0)
    if req_count is None or req_count <= 0 or obs_err is None:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="max_error_rate",
                status="missing",
                observed_value=None,
                threshold=guardrails.max_error_rate,
                comparison_operator="<=",
                unit="ratio",
                reason_code="ZERO_REQUEST_SAMPLE",
                explanation="Cannot compute error rate with 0 or missing requests.",
            )
        )
    else:
        err_ok = obs_err <= guardrails.max_error_rate
        checks.append(
            GuardrailCheckResult(
                guardrail_id="max_error_rate",
                status="passed" if err_ok else "failed",
                observed_value=obs_err,
                threshold=guardrails.max_error_rate,
                comparison_operator="<=",
                unit="ratio",
                evidence_ids=list(telemetry.evidence_ids),
                reason_code=(
                    "ERROR_RATE_WITHIN_LIMIT" if err_ok else "ABSOLUTE_ERROR_RATE_BREACH"
                ),
                explanation=(
                    f"Error rate {obs_err:.4f} vs max {guardrails.max_error_rate:.4f}."
                ),
            )
        )

    # 10. Baseline-relative error degradation & 11. p95 latency degradation
    base_err = baseline.error_rate if baseline is not None else telemetry.baseline_error_rate
    base_p95 = (
        baseline.latency_ms.p95_ms
        if baseline is not None and baseline.latency_ms is not None
        else telemetry.baseline_p95_latency_ms
    )
    if base_err is None or obs_err is None:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="baseline_error_rate_degradation",
                status="missing",
                observed_value=None,
                threshold=guardrails.max_error_rate_increase_pp,
                comparison_operator="<=",
                unit="percentage_points",
                reason_code="MISSING_BASELINE_ERROR_RATE",
                explanation="Baseline error rate is unavailable; hold required.",
            )
        )
    else:
        delta_pp = 100.0 * (obs_err - base_err)
        pp_ok = delta_pp <= guardrails.max_error_rate_increase_pp
        checks.append(
            GuardrailCheckResult(
                guardrail_id="baseline_error_rate_degradation",
                status="passed" if pp_ok else "failed",
                observed_value=round(delta_pp, 4),
                threshold=guardrails.max_error_rate_increase_pp,
                comparison_operator="<=",
                unit="percentage_points",
                baseline_reference=baseline.snapshot_id if baseline else "inline_baseline",
                reason_code=(
                    "BASELINE_ERROR_WITHIN_LIMIT" if pp_ok else "BASELINE_ERROR_DEGRADATION"
                ),
                explanation=(
                    f"Error rate delta {delta_pp:.2f}pp vs "
                    f"max {guardrails.max_error_rate_increase_pp:.2f}pp."
                ),
            )
        )

    cur_p95 = telemetry.latency_ms.p95_ms if telemetry.latency_ms is not None else None
    if base_p95 is None or base_p95 <= 0.0 or cur_p95 is None:
        checks.append(
            GuardrailCheckResult(
                guardrail_id="p95_latency_degradation",
                status="missing",
                observed_value=None,
                threshold=guardrails.max_p95_latency_increase_percent,
                comparison_operator="<=",
                unit="percent",
                reason_code="MISSING_OR_ZERO_BASELINE_P95",
                explanation="Valid positive baseline p95 latency is required.",
            )
        )
    else:
        delta_lat = 100.0 * (cur_p95 - base_p95) / base_p95
        lat_ok = delta_lat <= guardrails.max_p95_latency_increase_percent
        checks.append(
            GuardrailCheckResult(
                guardrail_id="p95_latency_degradation",
                status="passed" if lat_ok else "failed",
                observed_value=round(delta_lat, 2),
                threshold=guardrails.max_p95_latency_increase_percent,
                comparison_operator="<=",
                unit="percent",
                baseline_reference=baseline.snapshot_id if baseline else "inline_baseline",
                reason_code="LATENCY_WITHIN_LIMIT" if lat_ok else "P95_LATENCY_BREACH",
                explanation=(
                    f"p95 latency delta {delta_lat:.1f}% vs "
                    f"max {guardrails.max_p95_latency_increase_percent:.1f}%."
                ),
            )
        )

    # Decision precedence: Rollback recommendation > Hold > Advance
    passed_ids = [c.guardrail_id for c in checks if c.status == "passed"]
    failed_ids = [c.guardrail_id for c in checks if c.status == "failed"]
    missing_ids = [c.guardrail_id for c in checks if c.status in ("missing", "invalid")]

    has_sample = req_ok and telemetry.observation_window_seconds >= min_win
    sec_failed = any(
        c.guardrail_id == "security_regression" and c.status == "failed" for c in checks
    )
    op_failed = any(
        c.guardrail_id
        in ("max_error_rate", "baseline_error_rate_degradation", "p95_latency_degradation")
        and c.status == "failed"
        for c in checks
    )

    next_stage_id: str | None = None
    idx = next((i for i, s in enumerate(plan.stages) if s.stage_id == stage.stage_id), -1)
    if idx >= 0 and idx + 1 < len(plan.stages):
        next_stage_id = plan.stages[idx + 1].stage_id

    if sec_failed or (op_failed and has_sample):
        decision_type = RolloutDecisionType.ROLLBACK_PROPOSED
        proposed_next: str | None = None
        explanation = f"Guardrail breach detected: {', '.join(failed_ids)}."
    elif missing_ids or failed_ids:
        decision_type = RolloutDecisionType.HOLD
        proposed_next = None
        explanation = (
            "Holding rollout due to missing/invalid/unmet prerequisites: "
            f"{', '.join(missing_ids or failed_ids)}."
        )
    elif next_stage_id is None:
        decision_type = RolloutDecisionType.HOLD
        proposed_next = None
        explanation = (
            "Final 100% stage passed all guardrails; ready for final completion assessment."
        )
    else:
        decision_type = RolloutDecisionType.ADVANCE
        proposed_next = next_stage_id
        explanation = (
            f"All guardrails passed for stage {stage.exposure_percentage}%; "
            f"propose advancing to {next_stage_id}."
        )

    decision = RolloutDecision(
        decision_id=f"rdec_{stage.stage_id}_{telemetry.snapshot_id}"[:64],
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
        current_stage_id=stage.stage_id,
        proposed_next_stage_id=proposed_next,
        decision_type=decision_type,
        evaluated_guardrails=[c.guardrail_id for c in checks],
        passed_guardrails=passed_ids,
        failed_guardrails=failed_ids,
        missing_evidence=missing_ids,
        explanation=explanation,
        evidence_ids=evidence_ids,
        approval_required=True,
        decided_at=now,
    )
    return checks, decision
