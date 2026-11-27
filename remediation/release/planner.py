"""Validated 5/25/50/100 RolloutPlan builder (Phase 09)."""

from __future__ import annotations

from shared.config import load_rollout_policy
from shared.identifiers import generate_prefixed_id
from shared.schemas import (
    RolloutPlan,
    RolloutPolicyConfig,
    RolloutStage,
)

from remediation.release.models import RecoveryEligibilityContext


def build_validated_rollout_plan(
    ctx: RecoveryEligibilityContext,
    *,
    policy: RolloutPolicyConfig | None = None,
    plan_id: str | None = None,
) -> RolloutPlan:
    """Build a strictly ordered, approval-gated RolloutPlan (default 5/25/50/100%)."""
    active_policy = policy or load_rollout_policy()
    pid = plan_id or generate_prefixed_id("rollout_plan")

    stages: list[RolloutStage] = []
    for pct in active_policy.stages_percent:
        stages.append(
            RolloutStage(
                stage_id=f"rstage_{pct}pct_{pid[-8:]}",
                exposure_percentage=pct,
                segment_configuration={"cohort_strategy": "deterministic_sha256_bucket"},
                minimum_observation_window_seconds=active_policy.minimum_observation_window_seconds,
                minimum_request_count=active_policy.minimum_request_count,
                required_metrics=[
                    "request_count",
                    "failed_request_count",
                    "error_rate",
                    "p95_latency_ms",
                    "security_regression_passed",
                ],
                guardrails=active_policy.guardrails,
                approval_required=True,
            )
        )

    revision = (
        ctx.deployment_evidence.source_revision
        if ctx.deployment_evidence is not None
        else (ctx.verified_patched_revision or "unknown_revision")
    )

    evidence_ids = list(ctx.evidence_references)
    if ctx.deployment_evidence is not None:
        evidence_ids.extend(ctx.deployment_evidence.evidence_ids)
    if ctx.patch_test_result is not None:
        evidence_ids.extend(ctx.patch_test_result.artifact_ids)
    if not evidence_ids:
        evidence_ids = ["art_rollout_plan_draft"]

    return RolloutPlan(
        plan_id=pid,
        incident_id=ctx.incident_id,
        environment=ctx.environment,
        target_feature=ctx.target_feature,
        target_implementation_revision=revision,
        stages=stages,
        guardrails=active_policy.guardrails,
        policy_version=active_policy.policy_version,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
    )
