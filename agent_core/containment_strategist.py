"""Deterministic Containment Strategist implementing ``ContainmentStrategistAgent``.

Evaluates blast radius, counterfactual impact, hard feasibility gates, and
multi-criteria policy ranking to produce human-approval-ready ``ContainmentProposal``
objects without any LLM calls or privileged Flagsmith mutations.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

from shared.config import load_containment_policy
from shared.enums import ContainmentReasonCode, ProposalType
from shared.exceptions import ContractValidationError
from shared.identifiers import generate_idempotency_token, generate_proposal_id
from shared.schemas import (
    ContainmentPolicyConfig,
    ContainmentProposal,
    CoverageFinding,
    DependencyGraph,
    DeploymentEvidence,
    FeatureState,
    Finding,
    MappingResult,
    RouteFlagRegistry,
    VerificationResult,
)

from agent_core.blast_radius import analyze_blast_radius
from agent_core.containment.engine import (
    build_verification_checklist,
    evaluate_containment_candidates,
    run_sensitivity_analysis,
)
from agent_core.containment.models import ContainmentAnalysisResult
from agent_core.context import Clock, ContainmentStrategistAgent, SystemClock


class DeterministicContainmentStrategist(ContainmentStrategistAgent):
    """Production-intended deterministic strategist implementing ``ContainmentStrategistAgent``."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        policy: ContainmentPolicyConfig | None = None,
        registry: RouteFlagRegistry | None = None,
        fixture_mode: bool = False,
    ) -> None:
        self._clock: Clock = clock or SystemClock()
        self._policy: ContainmentPolicyConfig = policy or load_containment_policy()
        self._registry = registry
        self._fixture_mode = fixture_mode

    async def analyze_containment(
        self,
        finding: Finding,
        mapping: MappingResult,
        dependency_graph: DependencyGraph,
        observed_features: Sequence[FeatureState],
        *,
        registry: RouteFlagRegistry | None = None,
        deployment_evidence: Sequence[DeploymentEvidence] = (),
        verification_results: Sequence[VerificationResult] = (),
        coverage_findings: Sequence[CoverageFinding] = (),
        application_revision: str | None = None,
        environment: str | None = None,
    ) -> ContainmentAnalysisResult:
        """Analyze blast radius, score candidates, and build proposal if safely actionable."""
        now = self._clock.now()
        active_reg = registry or self._registry
        br = analyze_blast_radius(
            finding,
            mapping,
            dependency_graph,
            registry=active_reg,
            observed_features=observed_features,
            deployment_evidence=deployment_evidence,
            verification_results=verification_results,
            application_revision=application_revision,
            environment=environment,
            fixture_mode=self._fixture_mode,
            evaluation_timestamp=now,
        )

        strategies, base_reasons, global_lims = evaluate_containment_candidates(
            finding=finding,
            mapping=mapping,
            blast_radius=br,
            observed_features=observed_features,
            policy=self._policy,
            total_graph_nodes=len(dependency_graph.nodes),
            registry=active_reg,
            deployment_evidence=deployment_evidence,
            verification_results=verification_results,
            coverage_findings=coverage_findings,
            evaluation_timestamp=now,
        )
        sensitivity = run_sensitivity_analysis(
            strategies,
            total_graph_nodes=len(dependency_graph.nodes),
            policy_version=self._policy.policy_version,
        )
        checklist = build_verification_checklist(
            finding=finding,
            mapping=mapping,
            blast_radius=br,
        )

        feasible_opts = [
            s.option for s in strategies if s.option.feasible and s.execution_supported
        ]
        conditional_opts = [
            s.option for s in strategies if s.action_eligibility == "conditional"
        ]
        infeasible_opts = [
            s.option
            for s in strategies
            if not s.option.feasible and s.action_eligibility != "conditional"
        ]
        winner = feasible_opts[0] if feasible_opts else None

        proposal: ContainmentProposal | None = None
        all_reasons = set(base_reasons)
        if winner is not None and winner.proposed_target is not None:
            target_flag = winner.proposed_target
            expected_enabled: bool | None = None
            target_env = environment or finding.environment or dependency_graph.environment
            for fs in observed_features:
                if fs.feature_name == target_flag and fs.environment == target_env:
                    expected_enabled = fs.enabled
                    break

            proposal = ContainmentProposal.with_computed_hash(
                proposal_id=generate_proposal_id(),
                incident_id=finding.incident_id,
                proposal_type=ProposalType.CONTAINMENT_FLAG_DISABLE,
                environment=target_env,
                flag_name=target_flag,
                desired_enabled=False,
                expected_current_enabled=expected_enabled,
                reason=(
                    f"Disable {target_flag} to contain {finding.category.value} on "
                    f"{mapping.affected_route or finding.affected_route}."
                ),
                alternatives=[
                    f"{s.option.title}: "
                    f"{', '.join(s.option.infeasibility_reasons) or 'ranked lower'}"
                    for s in strategies
                    if s.option.option_id != winner.option_id
                ],
                expected_disruption=(
                    f"Affected capabilities: {br.affected_capabilities}; "
                    f"preserved: {br.preserved_capabilities}."
                ),
                evidence_ids=list(mapping.evidence_ids or finding.evidence_ids),
                approval_required=True,
                registry_version=mapping.registry_version,
                policy_version=self._policy.policy_version,
                created_at=now,
                expires_at=now + timedelta(seconds=self._policy.default_proposal_ttl_seconds),
                idempotency_token=generate_idempotency_token(),
                rollback_considerations=[
                    f"Do not re-enable {target_flag} until a tested patch is verified and deployed."
                ],
                hash_version="v2",
                review_metadata={
                    "graph_fingerprint": br.graph_fingerprint,
                    "selected_strategy": winner.strategy_type.value,
                    "policy_version": self._policy.policy_version,
                },
            )
            all_reasons.add(ContainmentReasonCode.ELIGIBLE_FOR_PROPOSAL)
            ranking_explanation = (
                f"Selected {winner.title!r} (score={winner.relative_policy_score}) over "
                f"{len(strategies) - 1} alternatives."
            )
            manual_review = False
        else:
            all_reasons.add(ContainmentReasonCode.MANUAL_REVIEW_REQUIRED)
            ranking_explanation = (
                "No feasible executable single-flag strategy passed all safety gates; "
                "manual review or verification is required."
            )
            manual_review = True

        return ContainmentAnalysisResult(
            incident_id=finding.incident_id,
            finding_id=finding.finding_id,
            policy_version=self._policy.policy_version,
            blast_radius=br,
            recommended_option=winner,
            ranked_feasible_options=feasible_opts,
            conditional_options=conditional_opts,
            infeasible_options=infeasible_opts,
            evaluated_strategies=strategies,
            sensitivity=sensitivity,
            proposal=proposal,
            verification_checklist=checklist,
            manual_review_required=manual_review,
            reason_codes=sorted(all_reasons, key=lambda c: c.value),
            ranking_explanation=ranking_explanation,
            limitations=sorted(set(global_lims)),
            is_fixture_only=br.is_fixture_only,
        )

    async def propose_containment(
        self,
        finding: Finding,
        mapping: MappingResult,
        dependency_graph: DependencyGraph,
        observed_features: list[FeatureState],
    ) -> ContainmentProposal:
        """``ContainmentStrategistAgent`` protocol entry point returning ``ContainmentProposal``."""
        analysis = await self.analyze_containment(
            finding, mapping, dependency_graph, observed_features
        )
        if analysis.proposal is None:
            raise ContractValidationError(
                "No safe executable containment proposal could be generated.",
                context={
                    "incident_id": finding.incident_id,
                    "reason_codes": [c.value for c in analysis.reason_codes],
                },
            )
        return analysis.proposal
