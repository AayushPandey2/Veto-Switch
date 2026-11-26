# ADR-009: Explicitly Labeled Synthetic Telemetry

## Context
Hackathon and offline development environments often rely on simulated traffic metrics to demonstrate progressive release guardrails (5% → 25% → 50% → 100%) and rollback triggers.

## Decision
Require `MetricSnapshot.provenance` to explicitly declare `EvidenceProvenance.SYNTHETIC_TELEMETRY` when metrics are simulated, represent unknown metrics as `None` (never `0`), and mark illustrative guardrail thresholds in `RolloutPolicyConfig` with `is_demo_default=True`.

## Alternatives
1. Returning simulated metrics under generic telemetry schemas with no provenance flag.
2. Defaulting missing counts or error rates to `0` / `0.0`.

## Rationale
Explicit synthetic provenance prevents demonstration telemetry from ever being mistaken for measured production health, and distinguishing `None` from `0` enables fail-closed `hold` decisions when telemetry is absent.

## Consequences
- `RolloutDecision` fails closed (`hold`) whenever `missing_evidence` is non-empty.
- UI and `EvidenceReport` surfaces can render clear synthetic-data disclaimers.

## Known Limitations
Demonstration thresholds (`max_error_rate=0.02`, `minimum_request_count=100`, `minimum_observation_window_seconds=30`) are illustrative defaults, not statistically calibrated production SLOs.
