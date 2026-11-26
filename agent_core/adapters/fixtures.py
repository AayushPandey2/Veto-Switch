"""Explicitly labeled offline fixture adapters implementing future agent protocols.

WARNING:
    These adapters return static ``REFERENCE_FIXTURE`` and ``SYNTHETIC_TELEMETRY``
    models strictly for offline simulation and testing. They are NOT live LLM
    reasoning or real security/telemetry services.
"""

from __future__ import annotations

from datetime import timedelta

from shared.enums import (
    EvidenceCompleteness,
    EvidenceProvenance,
    IncidentState,
    MappingStatus,
    ProposalType,
    RolloutDecisionType,
)
from shared.identifiers import (
    generate_idempotency_token,
    generate_investigation_id,
    generate_proposal_id,
    generate_report_id,
    generate_rollout_decision_id,
)
from shared.schemas import (
    ArtifactReference,
    ContainmentProposal,
    DependencyGraph,
    EvidenceReport,
    FeatureState,
    Finding,
    IncidentEvent,
    InvestigationSummary,
    MappingResult,
    MetricSnapshot,
    RolloutDecision,
    RolloutPlan,
    RouteFlagRegistry,
)

from agent_core.context import (
    Clock,
    ContainmentStrategistAgent,
    EvidenceReporterAgent,
    FeatureMapperAgent,
    InvestigatorAgent,
    ReleaseManagerAgent,
    SystemClock,
)


class FixtureInvestigatorAdapter(InvestigatorAgent):
    """Fixture adapter returning a labeled REFERENCE_FIXTURE InvestigationSummary."""

    async def investigate(
        self,
        finding: Finding,
        evidence_artifacts: list[ArtifactReference],
    ) -> InvestigationSummary:
        return InvestigationSummary(
            investigation_id=generate_investigation_id(),
            finding_id=finding.finding_id,
            incident_id=finding.incident_id,
            executive_summary=(
                f"[FIXTURE] Investigation for {finding.category.value} on "
                f"{finding.affected_route or finding.affected_component}."
            ),
            technical_explanation=(
                "Reference fixture explanation; live LLM investigation deferred to Phase 03."
            ),
            affected_components=[finding.affected_component],
            observed_effects=[finding.observed_impact or "Fixture vulnerability impact."],
            verified_facts=[
                f"Finding {finding.finding_id} recorded with status={finding.status.value}."
            ],
            assumptions=["Fixture mode assumes demonstration route topology."],
            uncertainties=["Live runtime call traces are unavailable in fixture mode."],
            evidence_ids=[a.artifact_id for a in evidence_artifacts] or list(finding.evidence_ids),
            recommended_next_action="Map finding to declared feature flag.",
            reasoning_source=EvidenceProvenance.REFERENCE_FIXTURE,
        )


class FixtureFeatureMapperAdapter(FeatureMapperAgent):
    """Deterministic fixture mapper resolving routes from ``RouteFlagRegistry``."""

    async def map_finding_to_flag(
        self,
        finding: Finding,
        registry: RouteFlagRegistry,
        observed_features: list[FeatureState],
    ) -> MappingResult:
        for entry in registry.routes:
            if finding.affected_route and entry.route == finding.affected_route and entry.flags:
                flag = entry.flags[0]
                return MappingResult(
                    finding_id=finding.finding_id,
                    mapping_status=MappingStatus.MATCHED,
                    affected_route=entry.route,
                    matched_component=entry.component,
                    candidate_flags=[flag],
                    selected_flag=flag,
                    registry_version=registry.registry_version,
                    mapping_rationale=(
                        f"[FIXTURE] Matched route {entry.route!r} to declared flag {flag!r}."
                    ),
                    evidence_ids=list(finding.evidence_ids),
                    manual_review_required=False,
                )
        return MappingResult(
            finding_id=finding.finding_id,
            mapping_status=MappingStatus.UNMAPPED,
            affected_route=finding.affected_route,
            matched_component=finding.affected_component,
            candidate_flags=[],
            selected_flag=None,
            registry_version=registry.registry_version,
            mapping_rationale="[FIXTURE] No declared feature flag mapped for affected route.",
            evidence_ids=list(finding.evidence_ids),
            manual_review_required=True,
        )


class FixtureContainmentStrategistAdapter(ContainmentStrategistAgent):
    """Fixture adapter building a canonical-hashed ContainmentProposal."""

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock: Clock = clock or SystemClock()

    async def propose_containment(
        self,
        finding: Finding,
        mapping: MappingResult,
        dependency_graph: DependencyGraph,
        observed_features: list[FeatureState],
    ) -> ContainmentProposal:
        flag_name = mapping.selected_flag or "unmapped"
        expected_enabled: bool | None = None
        for fs in observed_features:
            if fs.feature_name == flag_name:
                expected_enabled = fs.enabled
                break
        now = self._clock.now()
        return ContainmentProposal.with_computed_hash(
            proposal_id=generate_proposal_id(),
            incident_id=finding.incident_id,
            proposal_type=ProposalType.CONTAINMENT_FLAG_DISABLE,
            environment=dependency_graph.environment,
            flag_name=flag_name,
            desired_enabled=False,
            expected_current_enabled=expected_enabled,
            reason=f"[FIXTURE] Disable {flag_name} to contain {finding.category.value}.",
            alternatives=["Switch to replacement implementation (pending verified deployment)."],
            expected_disruption=f"Route {mapping.affected_route or 'target'} falls back safely.",
            evidence_ids=list(finding.evidence_ids or mapping.evidence_ids),
            approval_required=True,
            registry_version=mapping.registry_version,
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            idempotency_token=generate_idempotency_token(),
            rollback_considerations=["Require tested patch and deployment before re-enabling."],
        )


class FixtureReleaseManagerAdapter(ReleaseManagerAgent):
    """Deterministic guardrail evaluator over synthetic/observed MetricSnapshot."""

    async def evaluate_rollout_stage(
        self,
        plan: RolloutPlan,
        telemetry: MetricSnapshot,
        baseline: MetricSnapshot | None,
    ) -> RolloutDecision:
        stage_id = plan.current_stage_id or plan.stages[0].stage_id
        stage = next((s for s in plan.stages if s.stage_id == stage_id), plan.stages[0])
        stage_idx = plan.stages.index(stage)
        next_stage_id = (
            plan.stages[stage_idx + 1].stage_id if stage_idx + 1 < len(plan.stages) else None
        )

        missing: list[str] = []
        failed: list[str] = []
        passed: list[str] = []

        if telemetry.request_count is None or telemetry.error_rate is None:
            missing.append("telemetry_request_or_error_rate")
        elif telemetry.request_count < stage.minimum_request_count:
            missing.append("minimum_request_count")
        else:
            if telemetry.error_rate > stage.guardrails.max_error_rate:
                failed.append("max_error_rate")
            else:
                passed.append("max_error_rate")

        if telemetry.security_regression_passed is not True:
            failed.append("security_regression_passed")
        else:
            passed.append("security_regression_passed")

        if baseline is not None and baseline.baseline_p95_latency_ms is not None:
            passed.append("baseline_available")

        if failed:
            decision_type = RolloutDecisionType.ROLLBACK_PROPOSED
            explanation = f"[FIXTURE] Guardrails failed: {failed}."
        elif missing:
            decision_type = RolloutDecisionType.HOLD
            explanation = f"[FIXTURE] Missing or insufficient telemetry: {missing}."
        else:
            decision_type = RolloutDecisionType.ADVANCE
            explanation = "[FIXTURE] All stage health and security guardrails satisfied."

        return RolloutDecision(
            decision_id=generate_rollout_decision_id(),
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            current_stage_id=stage.stage_id,
            proposed_next_stage_id=(
                next_stage_id if decision_type == RolloutDecisionType.ADVANCE else None
            ),
            decision_type=decision_type,
            evaluated_guardrails=passed + failed + missing,
            passed_guardrails=passed,
            failed_guardrails=failed,
            missing_evidence=missing,
            explanation=explanation,
            evidence_ids=list(telemetry.evidence_ids),
            approval_required=True,
        )


class FixtureEvidenceReporterAdapter(EvidenceReporterAgent):
    """Fixture adapter assembling an EvidenceReport from accepted events and artifacts."""

    async def build_report(
        self,
        incident_id: str,
        events: list[IncidentEvent],
        artifacts: list[ArtifactReference],
    ) -> EvidenceReport:
        return EvidenceReport(
            report_id=generate_report_id(),
            incident_id=incident_id,
            incident_status=IncidentState.CONTAINED if events else IncidentState.RECEIVED,
            timeline=list(events),
            artifact_references=list(artifacts),
            missing_evidence=["fixture_mode_report"],
            limitations=["[FIXTURE] Generated by FixtureEvidenceReporterAdapter."],
            completeness=EvidenceCompleteness.PARTIAL,
        )
