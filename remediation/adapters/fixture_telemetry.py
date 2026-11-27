"""Explicitly labeled synthetic telemetry provider for Phase 09 offline demos & evals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shared.enums import EvidenceProvenance
from shared.schemas import LatencyStats, MetricSnapshot

_BASE_TIME = datetime(2026, 11, 28, 3, 0, 0, tzinfo=UTC)


def make_synthetic_snapshot(
    scenario: str,
    *,
    incident_id: str = "inc_demo_09",
    environment: str = "demo-staging",
    feature_id: str = "search_v2",
    stage_percentage: int = 5,
    observed_at: datetime | None = None,
) -> MetricSnapshot:
    """Return a deterministic seeded MetricSnapshot for a named synthetic scenario."""
    ts = observed_at or _BASE_TIME
    base = {
        "snapshot_id": f"met_{scenario}_{stage_percentage}pct"[:64],
        "incident_id": incident_id,
        "environment": environment,
        "feature_id": feature_id,
        "observation_window_seconds": 45,
        "observed_at": ts,
        "request_count": 200,
        "failed_request_count": 2,
        "error_rate": 0.01,
        "latency_ms": LatencyStats(p50_ms=20.0, p95_ms=44.0, p99_ms=70.0),
        "baseline_error_rate": 0.005,
        "baseline_p95_latency_ms": 40.0,
        "security_regression_passed": True,
        "observed_rollout_stage_percentage": stage_percentage,
        "provenance": EvidenceProvenance.SYNTHETIC_TELEMETRY,
        "evidence_ids": [f"art_met_{scenario}"],
    }

    if scenario == "healthy":
        pass
    elif scenario == "high_error_rate":
        base.update({"failed_request_count": 10, "error_rate": 0.05})
    elif scenario == "baseline_relative_degradation":
        base.update({"failed_request_count": 4, "error_rate": 0.02, "baseline_error_rate": 0.002})
    elif scenario == "high_p95_latency":
        base.update(
            {
                "latency_ms": LatencyStats(p50_ms=35.0, p95_ms=130.0, p99_ms=180.0),
                "baseline_p95_latency_ms": 100.0,
            }
        )
    elif scenario == "insufficient_requests":
        base.update({"request_count": 40, "failed_request_count": 0, "error_rate": 0.0})
    elif scenario == "zero_requests":
        base.update({"request_count": 0, "failed_request_count": 0, "error_rate": 0.0})
    elif scenario == "insufficient_window":
        base.update({"observation_window_seconds": 15})
    elif scenario == "missing_security_result":
        base.update({"security_regression_passed": None})
    elif scenario == "confirmed_security_regression":
        base.update({"security_regression_passed": False})
    elif scenario == "stale_telemetry":
        base.update({"observed_at": ts - timedelta(hours=3)})
    elif scenario == "wrong_environment":
        base.update({"environment": "prod"})
    elif scenario == "incorrect_observed_exposure":
        base.update({"observed_rollout_stage_percentage": stage_percentage + 20})
    elif scenario == "missing_baseline":
        base.update({"baseline_error_rate": None, "baseline_p95_latency_ms": None})
    elif scenario == "contradictory_metrics":
        base.update({"request_count": 200, "failed_request_count": 50, "error_rate": 0.005})
    else:
        raise ValueError(f"Unknown synthetic telemetry scenario: {scenario!r}")

    return MetricSnapshot(**base)  # type: ignore[arg-type]
