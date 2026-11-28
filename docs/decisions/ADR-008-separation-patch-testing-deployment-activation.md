# ADR-008: Separation of Patch Testing, Deployment, and Activation

## Context
A candidate patch passing isolated tests does not mean the fixed code is running in staging/production, and toggling a Flagsmith feature flag does not deploy code. Conflating these steps risks re-enabling vulnerable code.

## Decision
Model `PatchTestResult`, `DeploymentEvidence`, and `FeatureState` as separate contracts with distinct lifecycle checks before progressive rollout (`RolloutPlan`) may proceed.

## Alternatives
1. Allowing `PatchStatus.PATCH_TESTED` to directly trigger feature-flag re-enablement.

## Rationale
Separating isolated verification from observed deployment (`deployment_status="observed"` and `addressable=True`) and Flagsmith readback prevents premature traffic exposure to unpatched code revisions.

## Consequences
- `RolloutPolicyConfig` defaults to `require_security_verification=True`, `require_deployment_evidence=True`, and `require_feature_state_readback=True`.

## Known Limitations
Requires `platform` to expose accurate revision/manifest telemetry via `DeploymentStateReader`.
