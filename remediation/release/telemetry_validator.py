"""Deterministic telemetry consistency and stage-binding validation."""

from __future__ import annotations

from shared.enums import EvidenceProvenance
from shared.schemas import MetricSnapshot, RolloutPlan, RolloutStage


def validate_stage_telemetry(
    *,
    plan: RolloutPlan,
    stage: RolloutStage,
    telemetry: MetricSnapshot,
    live_mode: bool = False,
) -> list[str]:
    """Return list of validation errors; empty list means telemetry is structurally valid."""
    errors: list[str] = []
    if telemetry.incident_id != plan.incident_id:
        errors.append("MetricSnapshot incident_id does not match RolloutPlan.")
    if telemetry.environment != plan.environment:
        errors.append("MetricSnapshot environment does not match RolloutPlan.")
    if telemetry.feature_id != plan.target_feature:
        errors.append("MetricSnapshot feature_id does not match RolloutPlan target_feature.")
    if live_mode and telemetry.provenance == EvidenceProvenance.SYNTHETIC_TELEMETRY:
        errors.append("Synthetic telemetry is not permitted in live operational mode.")
    if (
        telemetry.request_count is not None
        and telemetry.failed_request_count is not None
        and telemetry.error_rate is not None
        and telemetry.request_count > 0
    ):
        expected_err = telemetry.failed_request_count / telemetry.request_count
        if abs(expected_err - telemetry.error_rate) > 0.015:
            errors.append(
                "MetricSnapshot error_rate contradicts failed_request_count / request_count."
            )
    if (
        telemetry.observed_rollout_stage_percentage is not None
        and telemetry.observed_rollout_stage_percentage != stage.exposure_percentage
    ):
        errors.append(
            f"Observed exposure {telemetry.observed_rollout_stage_percentage}% "
            f"differs from stage {stage.exposure_percentage}%."
        )
    return errors
