# `remediation/` — Remediation and Recovery Intelligence

**Owner:** AI/ML Engineer 2

## Responsibilities

- AI-assisted candidate source-code patch generation (`patch_agent.py` — deferred)
- Bounded candidate patch validation & isolated test orchestration (`patch_tests.py` — deferred)
- Progressive release planning across configured exposure stages (`rollout_agent.py` — deferred)
- Progressive release planning across configured exposure stages (`rollout_agent.py`, `release/`, `policies.py` — implemented offline)
- Rollback Intelligence Engine (`rollback.py`, `recovery/` — implemented offline)
- Incident evidence aggregation & exportable `EvidenceReport` generation (`evidence.py`, `reporting/` — implemented offline)
- Incident evidence aggregation & exportable `EvidenceReport` generation (`evidence.py` — deferred)
- Deterministic rollout/recovery guardrail evaluation (`policies.py` — deferred)
- Prompt templates (`prompts/` — deferred)

## Dependencies & Security Boundaries

- Consumes contracts, schemas, enums, and exceptions strictly from [`shared/`](../shared/).
- Submits bounded patches only via `shared.contracts.PatchTestRunner` (no arbitrary shell execution).
- Reads deployment state and telemetry only via `DeploymentStateReader` and `TelemetryReader`.
- Never conflates patch testing with deployment, or deployment with feature flag activation.
- Never treats synthetic telemetry as live production telemetry.

## Phase 01 Status

Package boundary and `prompts/` directory established. Implementation modules are intentionally deferred per the Prompt 01 specification; see [`docs/implementation_status.md`](../docs/implementation_status.md).
