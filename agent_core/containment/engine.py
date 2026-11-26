"""Deterministic candidate generation, feasibility gates, scoring, ranking, and sensitivity."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from shared.enums import (
    ContainmentReasonCode,
    ContainmentStrategyType,
    DeploymentStatus,
    FeatureObservationStatus,
    FindingStatus,
    MappingStatus,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.identifiers import ensure_utc, generate_option_id
from shared.schemas import (
    ContainmentOption,
    ContainmentPolicyConfig,
    ContainmentPolicyWeights,
    DeploymentEvidence,
    FeatureState,
    Finding,
    MappingResult,
    RouteFlagRegistry,
    VerificationResult,
)

from agent_core.containment.models import (
    EvaluatedStrategy,
    ScoreBreakdown,
    SensitivityResult,
)
from agent_core.graph_intelligence.counterfactual import simulate_counterfactual
from agent_core.graph_intelligence.models import BlastRadiusResult, CounterfactualOutcome

_SENSITIVITY_PROFILES: dict[str, ContainmentPolicyWeights] = {
    "balanced": ContainmentPolicyWeights(
        residual_exposure=0.50,
        operational_disruption=0.25,
        dependency_impact=0.15,
        uncertainty=0.10,
    ),
    "security_first": ContainmentPolicyWeights(
        residual_exposure=0.70,
        operational_disruption=0.10,
        dependency_impact=0.10,
        uncertainty=0.10,
    ),
    "availability_sensitive": ContainmentPolicyWeights(
        residual_exposure=0.40,
        operational_disruption=0.40,
        dependency_impact=0.10,
        uncertainty=0.10,
    ),
}


def compute_policy_score(
    *,
    disruption: float,
    residual_risk: float,
    dependency_reach: int,
    total_graph_nodes: int,
    uncertainty: float,
    weights: ContainmentPolicyWeights,
    policy_version: str,
) -> ScoreBreakdown:
    """Compute deterministic bounded policy score in [0.0, 1.0] (higher = preferred)."""
    denom = max(total_graph_nodes, 1)
    norm_dep = min(max(dependency_reach / denom, 0.0), 1.0)
    d = min(max(disruption, 0.0), 1.0)
    r = min(max(residual_risk, 0.0), 1.0)
    u = min(max(uncertainty, 0.0), 1.0)

    contrib = {
        "residual_exposure": round(weights.residual_exposure * r, 6),
        "operational_disruption": round(weights.operational_disruption * d, 6),
        "dependency_impact": round(weights.dependency_impact * norm_dep, 6),
        "uncertainty": round(weights.uncertainty * u, 6),
    }
    loss = min(max(sum(contrib.values()), 0.0), 1.0)
    score = round(1.0 - loss, 6)
    return ScoreBreakdown(
        policy_version=policy_version,
        raw_inputs={
            "operational_disruption": round(d, 6),
            "residual_exposure": round(r, 6),
            "dependency_impact": round(norm_dep, 6),
            "uncertainty": round(u, 6),
        },
        weights={
            "residual_exposure": weights.residual_exposure,
            "operational_disruption": weights.operational_disruption,
            "dependency_impact": weights.dependency_impact,
            "uncertainty": weights.uncertainty,
        },
        weighted_contributions=contrib,
        loss=round(loss, 6),
        relative_policy_score=score,
    )


def _find_feature_state(
    flag_name: str,
    observed_features: Sequence[FeatureState],
    environment: str,
) -> FeatureState | None:
    matches = [
        fs
        for fs in observed_features
        if fs.feature_name == flag_name and fs.environment == environment
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda f: ensure_utc(f.observed_at), reverse=True)[0]


def _check_replacement_prerequisites(
    *,
    replacement_flag: str,
    environment: str,
    expected_revision: str | None,
    deployment_evidence: Sequence[DeploymentEvidence],
    verification_results: Sequence[VerificationResult],
) -> tuple[bool, list[str], list[ContainmentReasonCode]]:
    """Verify strict deployment, addressability, revision, and security test prerequisites."""
    reasons: list[str] = []
    codes: list[ContainmentReasonCode] = []

    matching_deps = [
        d
        for d in deployment_evidence
        if d.feature_name == replacement_flag and d.environment == environment
    ]
    if not matching_deps:
        reasons.append(f"Replacement {replacement_flag!r} has no deployment evidence.")
        codes.append(ContainmentReasonCode.REPLACEMENT_NOT_DEPLOYED)
        return False, reasons, codes

    dep = matching_deps[0]
    if dep.deployment_status != DeploymentStatus.OBSERVED or not dep.addressable:
        reasons.append(
            f"Replacement {replacement_flag!r} is not observed deployed and addressable."
        )
        codes.append(ContainmentReasonCode.REPLACEMENT_NOT_DEPLOYED)
        return False, reasons, codes

    if expected_revision and dep.source_revision != expected_revision:
        reasons.append(
            f"Replacement deployment revision {dep.source_revision!r} != {expected_revision!r}."
        )
        codes.append(ContainmentReasonCode.REPLACEMENT_REVISION_MISMATCH)
        return False, reasons, codes

    passing_ver = [
        v
        for v in verification_results
        if v.execution_status == TestExecutionStatus.TEST_PASSED
        and v.passed is True
        and v.phase in {VerificationPhase.AFTER_PATCH, VerificationPhase.AFTER_CONTAINMENT}
        and (expected_revision is None or v.tested_revision == expected_revision)
    ]
    if not passing_ver:
        reasons.append(
            f"Replacement {replacement_flag!r} lacks passing security/functional verification."
        )
        codes.append(ContainmentReasonCode.REPLACEMENT_NOT_VERIFIED)
        return False, reasons, codes

    return True, reasons, codes


def evaluate_containment_candidates(
    *,
    finding: Finding,
    mapping: MappingResult,
    blast_radius: BlastRadiusResult,
    observed_features: Sequence[FeatureState],
    policy: ContainmentPolicyConfig,
    total_graph_nodes: int,
    registry: RouteFlagRegistry | None = None,
    deployment_evidence: Sequence[DeploymentEvidence] = (),
    verification_results: Sequence[VerificationResult] = (),
    evaluation_timestamp: datetime,
    freshness_max_age_seconds: int = 300,
) -> tuple[list[EvaluatedStrategy], list[ContainmentReasonCode], list[str]]:
    """Generate, gate, simulate, score, and rank deterministic containment strategies."""
    eval_utc = ensure_utc(evaluation_timestamp)
    target_env = finding.environment or blast_radius.environment
    base_reasons: list[ContainmentReasonCode] = list(blast_radius.reason_codes)
    global_limitations: list[str] = list(blast_radius.limitations)

    # Global operational prerequisites
    mapping_actionable = (
        finding.status == FindingStatus.REPRODUCED
        and mapping.mapping_status == MappingStatus.MATCHED
        and bool(mapping.selected_flag)
        and not mapping.manual_review_required
        and blast_radius.graph_valid
    )
    if mapping.diagnostics is not None:
        elig = mapping.diagnostics.get("action_eligibility")
        if elig in {"hold", "blocked"}:
            mapping_actionable = False

    if finding.status != FindingStatus.REPRODUCED:
        base_reasons.append(ContainmentReasonCode.UNVERIFIED_FINDING)
    if mapping.mapping_status != MappingStatus.MATCHED or not mapping.selected_flag:
        base_reasons.append(ContainmentReasonCode.MAPPING_NOT_ACTIONABLE)

    selected_flag = mapping.selected_flag
    fs = (
        _find_feature_state(selected_flag, observed_features, target_env)
        if selected_flag
        else None
    )

    state_fresh = False
    already_disabled = False
    if selected_flag:
        if fs is None or fs.observation_status != FeatureObservationStatus.OBSERVED:
            base_reasons.append(ContainmentReasonCode.STALE_FEATURE_STATE)
            global_limitations.append(
                f"Missing or non-observed FeatureState for {selected_flag!r}."
            )
        else:
            age = (eval_utc - ensure_utc(fs.observed_at)).total_seconds()
            if age > freshness_max_age_seconds or age < -30:
                base_reasons.append(ContainmentReasonCode.STALE_FEATURE_STATE)
                global_limitations.append(
                    f"FeatureState for {selected_flag!r} is stale or out of clock bounds."
                )
            else:
                state_fresh = True
            if fs.enabled is False:
                already_disabled = True
                base_reasons.append(ContainmentReasonCode.FEATURE_ALREADY_DISABLED)

    candidates: list[EvaluatedStrategy] = []
    evidence_ids = list(mapping.evidence_ids or finding.evidence_ids)
    weights = policy.weights

    # --- Strategy A: Disable vulnerable feature flag ---
    if selected_flag:
        cf_disable: CounterfactualOutcome = simulate_counterfactual(
            strategy_id="strat_disable_flag",
            strategy_type=ContainmentStrategyType.DISABLE_FEATURE_FLAG,
            target_flag=selected_flag,
            desired_enabled=False,
            blast_radius=blast_radius,
            observed_features=observed_features,
            registry=registry,
        )
        infeas_reasons: list[str] = []
        s_codes: list[ContainmentReasonCode] = []
        if not mapping_actionable:
            infeas_reasons.append("Mapping or finding prerequisites are not actionable.")
            s_codes.append(ContainmentReasonCode.MAPPING_NOT_ACTIONABLE)
        if not state_fresh:
            infeas_reasons.append(f"Fresh FeatureState observation required for {selected_flag!r}.")
            s_codes.append(ContainmentReasonCode.STALE_FEATURE_STATE)
        if already_disabled:
            infeas_reasons.append(
                f"Feature {selected_flag!r} is already disabled; verification is required "
                "instead of redundant toggle."
            )
            s_codes.append(ContainmentReasonCode.FEATURE_ALREADY_DISABLED)
        if not cf_disable.fallback_behavior:
            infeas_reasons.append("No declared safe fallback behavior for target route.")
            s_codes.append(ContainmentReasonCode.MISSING_FALLBACK_EVIDENCE)

        feasible = len(infeas_reasons) == 0
        if feasible:
            s_codes.append(ContainmentReasonCode.ELIGIBLE_FOR_PROPOSAL)

        disruption = 0.25 if blast_radius.preserved_capabilities else 0.55
        residual_risk = 0.08 if cf_disable.potentially_blocked_vulnerable_paths else 0.60
        uncertainty = 0.15 if state_fresh and cf_disable.fallback_behavior else 0.50
        dep_reach = len(blast_radius.affected_route_nodes) + len(
            blast_radius.affected_implementation_nodes
        )
        breakdown = compute_policy_score(
            disruption=disruption,
            residual_risk=residual_risk,
            dependency_reach=dep_reach,
            total_graph_nodes=total_graph_nodes,
            uncertainty=uncertainty,
            weights=weights,
            policy_version=policy.policy_version,
        )
        opt = ContainmentOption(
            option_id=generate_option_id(),
            incident_id=finding.incident_id,
            strategy_type=ContainmentStrategyType.DISABLE_FEATURE_FLAG,
            title=f"Disable vulnerable feature flag {selected_flag}",
            proposed_target=selected_flag,
            feasible=feasible,
            prerequisites=["Human approval decision", "Post-containment security verification"],
            infeasibility_reasons=infeas_reasons,
            estimated_disruption=disruption,
            estimated_residual_risk=residual_risk,
            dependency_reach=dep_reach,
            uncertainty=uncertainty,
            relative_policy_score=breakdown.relative_policy_score,
            affected_nodes=sorted(
                set(blast_radius.affected_route_nodes)
                | set(blast_radius.affected_implementation_nodes)
            ),
            protected_nodes=list(blast_radius.unrelated_nodes),
            evidence_ids=evidence_ids,
            limitations=cf_disable.limitations,
        )
        candidates.append(
            EvaluatedStrategy(
                strategy_id="strat_disable_flag",
                strategy_priority=10,
                option=opt,
                counterfactual=cf_disable,
                score_breakdown=breakdown,
                reason_codes=sorted(set(s_codes), key=lambda c: c.value),
                execution_supported=feasible,
                requires_approval=True,
                authorized_for_execution=False,
                action_eligibility="eligible_for_proposal" if feasible else "infeasible",
            )
        )

    # --- Strategy B: Switch to replacement implementation (if any declared) ---
    for rep_node in blast_radius.potential_replacements:
        rep_flag = rep_node.replace("impl_", "")
        cf_rep = simulate_counterfactual(
            strategy_id=f"strat_replace_{rep_flag}",
            strategy_type=ContainmentStrategyType.SWITCH_TO_REPLACEMENT_FLAG,
            target_flag=selected_flag,
            desired_enabled=False,
            replacement_flag=rep_flag,
            blast_radius=blast_radius,
            observed_features=observed_features,
            registry=registry,
        )
        rep_ok, rep_reasons, rep_codes = _check_replacement_prerequisites(
            replacement_flag=rep_flag,
            environment=target_env,
            expected_revision=finding.repository_revision,
            deployment_evidence=deployment_evidence,
            verification_results=verification_results,
        )
        # Current single-flag ContainmentProposal cannot execute coordinated multi-flag switch
        rep_reasons.append(
            "Single-flag ContainmentProposal cannot atomically coordinate multi-flag replacement."
        )
        rep_codes.append(ContainmentReasonCode.UNSUPPORTED_MULTI_FLAG_ACTION)

        disruption = 0.05
        residual_risk = 0.05 if rep_ok else 0.70
        uncertainty = 0.20 if rep_ok else 0.75
        dep_reach = len(blast_radius.affected_route_nodes)
        breakdown = compute_policy_score(
            disruption=disruption,
            residual_risk=residual_risk,
            dependency_reach=dep_reach,
            total_graph_nodes=total_graph_nodes,
            uncertainty=uncertainty,
            weights=weights,
            policy_version=policy.policy_version,
        )
        opt = ContainmentOption(
            option_id=generate_option_id(),
            incident_id=finding.incident_id,
            strategy_type=ContainmentStrategyType.SWITCH_TO_REPLACEMENT_FLAG,
            title=f"Switch traffic to replacement implementation {rep_flag}",
            proposed_target=rep_flag,
            feasible=False,
            prerequisites=[
                f"Observed deployment of {rep_flag}",
                f"Passing security verification for {rep_flag}",
                "Multi-flag atomic execution support",
            ],
            infeasibility_reasons=rep_reasons,
            estimated_disruption=disruption,
            estimated_residual_risk=residual_risk,
            dependency_reach=dep_reach,
            uncertainty=uncertainty,
            relative_policy_score=breakdown.relative_policy_score,
            affected_nodes=list(blast_radius.affected_route_nodes),
            protected_nodes=list(blast_radius.unrelated_nodes),
            evidence_ids=evidence_ids,
            limitations=cf_rep.limitations,
        )
        candidates.append(
            EvaluatedStrategy(
                strategy_id=f"strat_replace_{rep_flag}",
                strategy_priority=20,
                option=opt,
                counterfactual=cf_rep,
                score_breakdown=breakdown,
                reason_codes=sorted(set(rep_codes), key=lambda c: c.value),
                execution_supported=False,
                requires_approval=True,
                authorized_for_execution=False,
                action_eligibility="conditional" if rep_ok else "infeasible",
            )
        )

    # --- Strategy C: Broad application shutdown (comparison / manual-only) ---
    cf_broad = simulate_counterfactual(
        strategy_id="strat_broad_shutdown",
        strategy_type=ContainmentStrategyType.MANUAL_MITIGATION_REQUIRED,
        target_flag=None,
        desired_enabled=None,
        blast_radius=blast_radius,
        observed_features=observed_features,
        broad_shutdown=True,
    )
    broad_reach = max(total_graph_nodes - 1, 1)
    broad_breakdown = compute_policy_score(
        disruption=0.95,
        residual_risk=0.05,
        dependency_reach=broad_reach,
        total_graph_nodes=total_graph_nodes,
        uncertainty=0.20,
        weights=weights,
        policy_version=policy.policy_version,
    )
    broad_opt = ContainmentOption(
        option_id=generate_option_id(),
        incident_id=finding.incident_id,
        strategy_type=ContainmentStrategyType.MANUAL_MITIGATION_REQUIRED,
        title="Broad application shutdown / emergency isolation (manual only)",
        proposed_target=None,
        feasible=False,
        prerequisites=["Manual operator emergency intervention"],
        infeasibility_reasons=[
            "No application-wide Flagsmith control exists; high operational disruption."
        ],
        estimated_disruption=0.95,
        estimated_residual_risk=0.05,
        dependency_reach=broad_reach,
        uncertainty=0.20,
        relative_policy_score=broad_breakdown.relative_policy_score,
        affected_nodes=sorted(
            set(blast_radius.affected_route_nodes) | set(blast_radius.unrelated_nodes)
        ),
        protected_nodes=[],
        evidence_ids=evidence_ids,
        limitations=cf_broad.limitations,
    )
    candidates.append(
        EvaluatedStrategy(
            strategy_id="strat_broad_shutdown",
            strategy_priority=90,
            option=broad_opt,
            counterfactual=cf_broad,
            score_breakdown=broad_breakdown,
            reason_codes=[ContainmentReasonCode.UNKNOWN_CONTROL_CAPABILITY],
            execution_supported=False,
            requires_approval=True,
            authorized_for_execution=False,
            action_eligibility="manual_only",
        )
    )

    # Sort deterministically: feasible first, then execution_supported, lowest residual risk,
    # highest relative_policy_score, lowest disruption, priority, strategy_id
    ranked = sorted(
        candidates,
        key=lambda s: (
            0 if s.option.feasible else 1,
            0 if s.execution_supported else 1,
            s.option.estimated_residual_risk,
            -s.option.relative_policy_score,
            s.option.estimated_disruption,
            s.strategy_priority,
            s.strategy_id,
        ),
    )

    return ranked, sorted(set(base_reasons), key=lambda c: c.value), global_limitations


def run_sensitivity_analysis(
    strategies: Sequence[EvaluatedStrategy],
    *,
    total_graph_nodes: int,
    policy_version: str,
) -> SensitivityResult:
    """Check whether the winning feasible strategy remains stable under alternate weights."""
    feasible = [s for s in strategies if s.option.feasible and s.execution_supported]
    if not feasible:
        return SensitivityResult(
            stable=True,
            baseline_winner_id=None,
            profile_winners={k: None for k in _SENSITIVITY_PROFILES},
            notes=["No feasible executable strategy exists under any weight profile."],
        )

    baseline_winner = feasible[0].strategy_id
    profile_winners: dict[str, str | None] = {}
    for pname, weights in _SENSITIVITY_PROFILES.items():
        rescored = sorted(
            feasible,
            key=lambda s: (
                -compute_policy_score(
                    disruption=s.option.estimated_disruption,
                    residual_risk=s.option.estimated_residual_risk,
                    dependency_reach=s.option.dependency_reach,
                    total_graph_nodes=total_graph_nodes,
                    uncertainty=s.option.uncertainty,
                    weights=weights,
                    policy_version=policy_version,
                ).relative_policy_score,
                s.strategy_priority,
                s.strategy_id,
            ),
        )
        profile_winners[pname] = rescored[0].strategy_id

    stable = len(set(profile_winners.values())) == 1
    return SensitivityResult(
        stable=stable,
        baseline_winner_id=baseline_winner,
        profile_winners=profile_winners,
        notes=[
            "Evaluated only strategies passing mandatory hard safety gates."
        ],
    )


def build_verification_checklist(
    *,
    finding: Finding,
    mapping: MappingResult,
    blast_radius: BlastRadiusResult,
) -> list[str]:
    """Build structured post-containment verification checklist using known test IDs."""
    checklist: list[str] = []
    if finding.affected_route == "/search" or mapping.selected_flag == "search_v1":
        checklist.append(
            "Run registered security regression test 'sqli_search' (after_containment)."
        )
    elif finding.affected_route == "/files" or mapping.selected_flag == "files_v1":
        checklist.append(
            "Run registered security regression test 'traversal_files' (after_containment)."
        )
    else:
        checklist.append("Run category-specific post-containment security regression test.")

    if blast_radius.known_security_entry_points:
        checklist.append(
            f"Verify all declared entry points {blast_radius.known_security_entry_points} "
            "block the exploit."
        )
    if mapping.selected_flag:
        checklist.append(
            "Verify application-observed feature state on /health reports "
            f"{mapping.selected_flag}=false."
        )
    checklist.append("Run unrelated functional smoke tests ('smoke_status', 'smoke_catalog').")
    return checklist
