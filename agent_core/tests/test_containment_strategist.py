"""Tests for ContainmentStrategist, feasibility gates, proposal v2 hash, and orchestration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agent_core.containment_strategist import DeterministicContainmentStrategist
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.demos.blast_radius_demos import run_blast_radius_demos
from agent_core.evaluations.blast_radius_evaluator import run_blast_radius_evaluation
from agent_core.events import build_incident_event
from agent_core.flag_mapper import DeterministicFlagMapper
from agent_core.mapping.models import MappingContext
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.policies import validate_containment_proposal_output
from agent_core.replay import replay_incident
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.config import load_containment_policy, load_dependency_graph, load_route_registry
from shared.enums import (
    ActorType,
    ArtifactType,
    ContainmentReasonCode,
    ContainmentStrategyType,
    DeploymentStatus,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    IncidentState,
    MappingStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.identifiers import generate_incident_id
from shared.schemas import (
    ArtifactReference,
    DeploymentEvidence,
    FeatureState,
    Finding,
    MappingResult,
    VerificationResult,
)
from shared.serialization import sha256_text

NOW = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)


def _obs(flag: str, *, enabled: bool = True, age_s: int = 5) -> FeatureState:
    return FeatureState(
        environment="demo-staging",
        feature_id=f"fs_{flag}",
        feature_name=flag,
        observation_status=FeatureObservationStatus.OBSERVED,
        enabled=enabled,
        observed_at=NOW - timedelta(seconds=age_s),
        state_version="v1",
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
    )


@pytest.mark.asyncio
async def test_strategist_ranks_disable_over_unverified_replacement_and_broad_shutdown() -> None:
    reg = load_route_registry()
    graph = load_dependency_graph()
    strategist = DeterministicContainmentStrategist(
        clock=FixedClock(NOW),
        policy=load_containment_policy(),
        registry=reg,
        fixture_mode=True,
    )
    finding = Finding(
        finding_id="fnd_cs_01",
        incident_id="inc_cs_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_cs_01"],
        repository_revision=reg.application_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    mapping = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.MATCHED,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["search_v1", "search_v2"],
        selected_flag="search_v1",
        registry_version=reg.registry_version,
        mapping_rationale="Verified search_v1.",
        evidence_ids=["art_cs_01"],
        manual_review_required=False,
    )
    analysis = await strategist.analyze_containment(
        finding,
        mapping,
        graph,
        [_obs("search_v1", enabled=True), _obs("search_v2", enabled=False)],
    )
    assert len(analysis.evaluated_strategies) >= 3
    assert analysis.recommended_option is not None
    assert analysis.recommended_option.strategy_type == ContainmentStrategyType.DISABLE_FEATURE_FLAG
    assert analysis.recommended_option.proposed_target == "search_v1"
    assert analysis.proposal is not None
    assert analysis.proposal.hash_version == "v2"
    assert analysis.proposal.verify_hash() is True
    assert analysis.proposal.desired_enabled is False
    assert analysis.proposal.approval_required is True
    assert analysis.sensitivity.stable is True


@pytest.mark.asyncio
async def test_replacement_requires_deployment_verification_and_single_action_support() -> None:
    reg = load_route_registry()
    graph = load_dependency_graph()
    strategist = DeterministicContainmentStrategist(
        clock=FixedClock(NOW), registry=reg, fixture_mode=True
    )
    finding = Finding(
        finding_id="fnd_cs_rep",
        incident_id="inc_cs_rep",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_cs_rep"],
        repository_revision="rev_1",
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    mapping = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.MATCHED,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["search_v1", "search_v2"],
        selected_flag="search_v1",
        registry_version=reg.registry_version,
        mapping_rationale="Verified search_v1.",
        evidence_ids=["art_cs_rep"],
        manual_review_required=False,
    )
    dep = DeploymentEvidence(
        deployment_id="dep_search_v2",
        environment="demo-staging",
        implementation_id="search_v2",
        feature_name="search_v2",
        source_revision="rev_1",
        implementation_hash="a" * 64,
        deployed_at=NOW,
        deployment_status=DeploymentStatus.OBSERVED,
        addressable=True,
        evidence_ids=["art_dep_01"],
    )
    ver = VerificationResult(
        verification_id="ver_search_v2",
        incident_id="inc_cs_rep",
        test_id="sqli_search",
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision="rev_1",
    )
    analysis = await strategist.analyze_containment(
        finding,
        mapping,
        graph,
        [_obs("search_v1"), _obs("search_v2", enabled=False)],
        deployment_evidence=[dep],
        verification_results=[ver],
    )
    rep_strat = next(
        s
        for s in analysis.evaluated_strategies
        if s.option.strategy_type == ContainmentStrategyType.SWITCH_TO_REPLACEMENT_FLAG
    )
    assert rep_strat.action_eligibility == "conditional"
    assert ContainmentReasonCode.UNSUPPORTED_MULTI_FLAG_ACTION in rep_strat.reason_codes


@pytest.mark.asyncio
async def test_proposal_v2_hash_mutation_and_policy_validation() -> None:
    reg = load_route_registry()
    graph = load_dependency_graph()
    strategist = DeterministicContainmentStrategist(
        clock=FixedClock(NOW), registry=reg, fixture_mode=True
    )
    finding = Finding(
        finding_id="fnd_hash_01",
        incident_id="inc_hash_01",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        affected_route="/files",
        affected_component="file_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_hash_01"],
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    mapping = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.MATCHED,
        affected_route="/files",
        matched_component="file_service",
        candidate_flags=["files_v1"],
        selected_flag="files_v1",
        registry_version=reg.registry_version,
        mapping_rationale="Verified files_v1.",
        evidence_ids=["art_hash_01"],
        manual_review_required=False,
    )
    prop = await strategist.propose_containment(finding, mapping, graph, [_obs("files_v1")])
    assert prop.verify_hash() is True

    # Mutating review-relevant fields invalidates v2 proposal_hash
    for bad_update in (
        {"reason": "Tampered reason"},
        {"expected_disruption": "Tampered disruption"},
        {"expires_at": NOW + timedelta(days=30)},
        {"rollback_considerations": ["Re-enable immediately"]},
    ):
        tampered = prop.model_copy(update=bad_update)
        assert tampered.verify_hash() is False
        with pytest.raises(ContractValidationError):
            validate_containment_proposal_output(
                tampered, finding=finding, mapping=mapping, registry=reg
            )

    # Proposal with desired_enabled=True is rejected even if re-hashed
    enable_prop = prop.model_copy(update={"desired_enabled": True})
    enable_prop = enable_prop.model_copy(update={"proposal_hash": enable_prop.compute_hash()})
    with pytest.raises(ContractValidationError):
        validate_containment_proposal_output(
            enable_prop, finding=finding, mapping=mapping, registry=reg
        )

    # Legacy v1 proposal rejected when require_v2_hash=True
    v1_prop = prop.model_copy(update={"hash_version": "v1"})
    v1_prop = v1_prop.model_copy(update={"proposal_hash": v1_prop.compute_hash()})
    with pytest.raises(ContractValidationError):
        validate_containment_proposal_output(
            v1_prop, finding=finding, mapping=mapping, registry=reg, require_v2_hash=True
        )


@pytest.mark.asyncio
async def test_orchestrator_containment_stops_at_awaiting_approval_and_replays() -> None:
    reg = load_route_registry()
    graph = load_dependency_graph()
    repo = InMemoryOrchestrationRepository()
    clock = FixedClock(NOW)
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=reg,
        clock=clock,
        fixture_mode=True,
        feature_mapper=DeterministicFlagMapper(
            evidence_repository=repo, clock=clock, fixture_mode=True
        ),
        containment_strategist=DeterministicContainmentStrategist(
            clock=clock, registry=reg, fixture_mode=True
        ),
    )
    inc_id = generate_incident_id()
    raw = b"reproduction proof"
    art = ArtifactReference(
        artifact_id="art_e2e_05",
        incident_id=inc_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash=sha256_text(raw.decode("utf-8")),
        storage_ref="repro/e2e_05.log",
        created_at=NOW,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(raw),
        source_revision=reg.application_revision,
    )
    await repo.store_artifact(art, raw)
    finding = Finding(
        finding_id="fnd_e2e_05",
        incident_id=inc_id,
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=[art.artifact_id],
        repository_revision=reg.application_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    sys_prod = ProducerContext(
        producer_id="platform_api",
        actor_type=ActorType.SYSTEM,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="deterministic_engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    ver_prod = ProducerContext(
        producer_id="authorized_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    inc = await orch.create_incident(finding, sys_prod)
    await orch.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.VERIFICATION_REQUESTED,
            actor="deterministic_engine",
            actor_type=ActorType.DETERMINISTIC_ENGINE,
            sequence_number=2,
            correlation_id=inc.correlation_id,
            timestamp_utc=NOW,
        ),
        producer_context=eng_prod,
    )
    await orch.process_event(
        build_incident_event(
            incident_id=inc.incident_id,
            event_type=EventType.REPRODUCTION_CONFIRMED,
            actor="authorized_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=3,
            correlation_id=inc.correlation_id,
            evidence_ids=[art.artifact_id],
            timestamp_utc=NOW,
        ),
        producer_context=ver_prod,
        transition_context=TransitionContext(
            producer_context=ver_prod, clock=clock, fixture_mode=True
        ),
    )
    states = [_obs("search_v1"), _obs("search_v2", enabled=False)]
    map_out, _ = await orch.execute_mapping(
        finding=finding,
        producer_context=eng_prod,
        observed_features=states,
        mapping_context=MappingContext(
            finding=finding,
            observed_implementation="search_v1",
            application_revision=reg.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=NOW,
        ),
    )
    analysis, cont_res = await orch.execute_containment_analysis(
        finding=finding,
        mapping=map_out.mapping_result,
        dependency_graph=graph,
        observed_features=states,
        producer_context=eng_prod,
    )
    assert analysis is not None and analysis.proposal is not None
    assert cont_res.accepted is True
    assert cont_res.current_state == IncidentState.AWAITING_APPROVAL
    assert len(cont_res.pending_requests) == 0

    events = await repo.list_incident_events(inc.incident_id)
    assert replay_incident(events).current_state == IncidentState.AWAITING_APPROVAL


@pytest.mark.asyncio
async def test_phase_05_demos_and_evaluator(tmp_path: Path) -> None:
    demos = await run_blast_radius_demos()
    assert len(demos) == 5
    report = await run_blast_radius_evaluation(reports_dir=tmp_path)
    assert report["failed_cases"] == 0
    assert report["unsafe_recommended_executable_options"] == 0
