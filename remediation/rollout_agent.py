"""Phase 09 Progressive Rollout Intelligence Agent and compatible public interface."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_core.context import ReleaseManagerAgent
from shared.config import load_rollout_policy
from shared.enums import (
    EvidenceProvenance,
    RolloutDecisionType,
)
from shared.schemas import (
    LatencyStats,
    MetricSnapshot,
    RolloutDecision,
    RolloutPlan,
    RolloutPolicyConfig,
    RolloutStage,
)

from remediation.policies import evaluate_stage_guardrails
from remediation.release.dashboard import build_phase10_rollback_handoff
from remediation.release.eligibility import evaluate_recovery_eligibility
from remediation.release.models import (
    EligibilityGateResult,
    RecoveryEligibilityContext,
    RolloutEvaluationBundle,
    StageActionProposal,
)
from remediation.release.planner import build_validated_rollout_plan
from remediation.release.stage_proposal import build_stage_action_proposal


class DeterministicReleaseManager(ReleaseManagerAgent):
    """Deterministic Phase 09 Release Intelligence Engine (zero mandatory LLM calls)."""

    def __init__(self, *, policy: RolloutPolicyConfig | None = None) -> None:
        self._policy = policy or load_rollout_policy()

    def plan_rollout(
        self,
        ctx: RecoveryEligibilityContext,
    ) -> tuple[EligibilityGateResult, RolloutPlan]:
        """Validate recovery eligibility and construct a 5/25/50/100 RolloutPlan."""
        gate = evaluate_recovery_eligibility(ctx)
        plan = build_validated_rollout_plan(ctx, policy=self._policy)
        return gate, plan

    async def evaluate_rollout_stage(
        self,
        plan: RolloutPlan,
        telemetry: MetricSnapshot,
        baseline: MetricSnapshot | None,
        *,
        current_stage_id: str | None = None,
        observed_exposure: int | None = None,
        observed_revision: str | None = None,
        live_mode: bool = False,
        evaluation_time: datetime | None = None,
    ) -> RolloutDecision:
        """Evaluate stage telemetry against deterministic guardrails."""
        stage = self._resolve_stage(plan, telemetry, current_stage_id)
        _, decision = evaluate_stage_guardrails(
            plan=plan,
            stage=stage,
            telemetry=telemetry,
            baseline=baseline,
            policy=self._policy,
            observed_exposure=observed_exposure,
            expected_revision=plan.target_implementation_revision,
            observed_revision=observed_revision,
            live_mode=live_mode,
            evaluation_time=evaluation_time,
        )
        return decision

    def evaluate_stage_full(
        self,
        *,
        plan: RolloutPlan,
        telemetry: MetricSnapshot,
        baseline: MetricSnapshot | None = None,
        current_stage_id: str | None = None,
        observed_exposure: int | None = None,
        observed_revision: str | None = None,
        live_mode: bool = False,
        evaluation_time: datetime | None = None,
        deployment_evidence_id: str = "dep_verified",
    ) -> RolloutEvaluationBundle:
        """Evaluate stage guardrails and produce next-stage proposal or rollback handoff."""
        stage = self._resolve_stage(plan, telemetry, current_stage_id)
        checks, decision = evaluate_stage_guardrails(
            plan=plan,
            stage=stage,
            telemetry=telemetry,
            baseline=baseline,
            policy=self._policy,
            observed_exposure=observed_exposure,
            expected_revision=plan.target_implementation_revision,
            observed_revision=observed_revision,
            live_mode=live_mode,
            evaluation_time=evaluation_time,
        )
        next_proposal: StageActionProposal | None = None
        if (
            decision.decision_type == RolloutDecisionType.ADVANCE
            and decision.proposed_next_stage_id is not None
        ):
            next_stage = next(
                s for s in plan.stages if s.stage_id == decision.proposed_next_stage_id
            )
            next_proposal = build_stage_action_proposal(
                plan=plan,
                stage=next_stage,
                previous_stage_id=stage.stage_id,
                expected_current_exposure=stage.exposure_percentage,
                deployment_evidence_identity=deployment_evidence_id,
                verification_evidence=list(decision.evidence_ids),
                decision_identity=decision.decision_id,
                created_at=decision.decided_at,
            )

        rollback_handoff = None
        if decision.decision_type == RolloutDecisionType.ROLLBACK_PROPOSED:
            rollback_handoff = build_phase10_rollback_handoff(
                plan=plan,
                decision=decision,
                observed_exposure=observed_exposure or telemetry.observed_rollout_stage_percentage,
            )

        return RolloutEvaluationBundle(
            plan=plan,
            decision=decision,
            guardrail_checks=checks,
            next_stage_proposal=next_proposal,
            rollback_handoff=rollback_handoff,
            provenance=EvidenceProvenance.DETERMINISTIC_REASONING,
        )

    @staticmethod
    def _resolve_stage(
        plan: RolloutPlan,
        telemetry: MetricSnapshot,
        current_stage_id: str | None,
    ) -> RolloutStage:
        if current_stage_id is not None:
            for s in plan.stages:
                if s.stage_id == current_stage_id:
                    return s
        if telemetry.observed_rollout_stage_percentage is not None:
            for s in plan.stages:
                if s.exposure_percentage == telemetry.observed_rollout_stage_percentage:
                    return s
        return plan.stages[0]


def build_rollout_plan(incident_id: str, patch_status: dict[str, Any]) -> dict[str, Any]:
    """Compatible public roadmap interface returning a diagnostic or validated plan dict."""
    rev = str(patch_status.get("revision") or patch_status.get("patched_revision") or "unknown")
    ctx = RecoveryEligibilityContext(
        incident_id=incident_id,
        verified_patched_revision=rev,
        target_feature=str(patch_status.get("target_feature") or "search_v2"),
        environment=str(patch_status.get("environment") or "demo-staging"),
        supports_segment_targeting=bool(patch_status.get("supports_segment_targeting", True)),
        evidence_references=list(patch_status.get("evidence_ids") or ["art_roadmap_plan"]),
    )
    mgr = DeterministicReleaseManager()
    gate, plan = mgr.plan_rollout(ctx)
    payload = plan.model_dump(mode="json")
    payload["eligibility"] = gate.model_dump(mode="json")
    return payload


def evaluate_rollout_stage(
    plan: dict[str, Any],
    metrics: dict[str, Any],
    observed_state: dict[str, Any],
) -> dict[str, Any]:
    """Compatible public roadmap interface for deterministic stage evaluation."""
    plan_obj = RolloutPlan.model_validate({k: v for k, v in plan.items() if k != "eligibility"})
    req_count = int(metrics.get("request_count", 0))
    fail_count = int(metrics.get("failed_request_count", 0))
    err_rate = float(metrics.get("error_rate", (fail_count / req_count) if req_count > 0 else 0.0))
    p95 = float(metrics.get("p95_latency_ms", 40.0))
    snap = MetricSnapshot(
        snapshot_id=str(metrics.get("snapshot_id") or "met_compat_01"),
        incident_id=plan_obj.incident_id,
        environment=plan_obj.environment,
        feature_id=plan_obj.target_feature,
        observation_window_seconds=int(metrics.get("observation_window_seconds", 45)),
        request_count=req_count,
        failed_request_count=fail_count,
        error_rate=err_rate,
        latency_ms=LatencyStats(p50_ms=p95 * 0.5, p95_ms=p95, p99_ms=p95 * 1.3),
        baseline_error_rate=metrics.get("baseline_error_rate"),
        baseline_p95_latency_ms=metrics.get("baseline_p95_latency_ms"),
        security_regression_passed=metrics.get("security_regression_passed"),
        observed_rollout_stage_percentage=observed_state.get("observed_exposure"),
        provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        evidence_ids=list(metrics.get("evidence_ids") or ["art_compat_met"]),
    )
    mgr = DeterministicReleaseManager()
    bundle = mgr.evaluate_stage_full(
        plan=plan_obj,
        telemetry=snap,
        current_stage_id=observed_state.get("stage_id"),
        observed_exposure=observed_state.get("observed_exposure"),
    )
    return bundle.decision.model_dump(mode="json")
