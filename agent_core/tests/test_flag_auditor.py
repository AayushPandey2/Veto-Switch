"""Comprehensive unit, adversarial, and integration tests for Phase 06 Flag Coverage Auditor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from agent_core.containment_strategist import DeterministicContainmentStrategist
from agent_core.context import FixedClock
from agent_core.coverage.dashboard import (
    serialize_coverage_dashboard,
    serialize_flags_coverage_endpoint,
)
from agent_core.coverage.models import SnapshotLimits
from agent_core.coverage.source_snapshot import (
    build_in_memory_snapshot,
    load_authorized_source_snapshot,
)
from agent_core.demos.coverage_demos import run_all_coverage_demos
from agent_core.evaluations.coverage_evaluator import evaluate_coverage_dataset
from agent_core.flag_auditor import audit_flag_coverage
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.config import load_dependency_graph, load_route_registry
from shared.enums import (
    ArtifactType,
    ContainmentReasonCode,
    CoverageApplicability,
    CoverageEvidenceSupport,
    CoverageReasonCode,
    CoverageStatus,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    MappingStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.schemas import FeatureState, Finding, MappingResult, VerificationResult

NOW = datetime(2026, 11, 28, 12, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_guarded_platform_routes_and_exemptions() -> None:
    src = """
@app.get("/search")
def search_route():
    states = provider.get_states(("search_v1", "search_v2"), identity=identity)
    if states["search_v2"] is FeatureState.ENABLED:
        return parameterized_search_documents()
    if states["search_v1"] is FeatureState.ENABLED:
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()

@app.get("/health")
def health():
    return health_response()
"""
    snap = build_in_memory_snapshot(
        application_id="platform_demo_app",
        environment="demo-staging",
        source_revision="rev-1",
        files={"app.py": src},
    )
    res = await audit_flag_coverage(snap, registry=load_route_registry(), is_fixture=True)
    assert res.summary.sensitive_routes == 1
    assert res.summary.protected == 1
    assert res.summary.exempt_routes == 1
    by_route = {a.route_identity.route: a for a in res.route_assessments}
    assert by_route["/search"].status == CoverageStatus.PROTECTED
    assert by_route["/health"].applicability == CoverageApplicability.EXEMPT


@pytest.mark.asyncio
async def test_alternate_entrypoint_bypass_detected_and_propagated() -> None:
    src = """
@app.get("/search")
def search_route():
    if provider.is_enabled("search_v1"):
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()

@app.get("/demo/direct")
def direct_bypass():
    return vulnerable_search_documents_for_demo()
"""
    snap = build_in_memory_snapshot(
        application_id="platform_demo_app",
        environment="demo-staging",
        source_revision="rev-2",
        files={"app.py": src},
    )
    res = await audit_flag_coverage(snap, is_fixture=True)
    by_route = {a.route_identity.route: a for a in res.route_assessments}
    assert by_route["/search"].status == CoverageStatus.PARTIALLY_PROTECTED
    assert by_route["/demo/direct"].status == CoverageStatus.UNPROTECTED
    assert CoverageReasonCode.ALTERNATE_ENTRYPOINT_BYPASS in res.reason_codes
    assert len(res.recommendations) == 2
    assert all(r.review_only for r in res.recommendations)


@pytest.mark.asyncio
async def test_adversarial_guard_patterns() -> None:
    src = """
@app.get("/log-only")
def log_only():
    if provider.is_enabled("search_v1"):
        logger.info("enabled")
    return vulnerable_search_documents_for_demo()

@app.get("/post-sink")
def post_sink():
    res = vulnerable_search_documents_for_demo()
    if provider.is_enabled("search_v1"):
        logger.info("too late")
    return res

@app.get("/or-bypass")
def or_bypass():
    if provider.is_enabled("search_v1") or provider.is_enabled("other_flag"):
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()

@app.get("/wrong-flag")
def wrong_flag():
    if provider.is_enabled("unrelated_flag"):
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()
"""
    snap = build_in_memory_snapshot(
        application_id="platform_demo_app",
        environment="demo-staging",
        source_revision="rev-3",
        files={"app.py": src},
    )
    res = await audit_flag_coverage(snap, is_fixture=True)
    by_route = {a.route_identity.route: a for a in res.route_assessments}
    assert by_route["/log-only"].status == CoverageStatus.UNPROTECTED
    assert CoverageReasonCode.FLAG_REFERENCE_ONLY in by_route["/log-only"].reason_codes
    assert by_route["/post-sink"].status == CoverageStatus.UNPROTECTED
    assert (
        CoverageReasonCode.GUARD_AFTER_SENSITIVE_OPERATION in by_route["/post-sink"].reason_codes
    )
    assert by_route["/or-bypass"].status == CoverageStatus.UNPROTECTED
    assert CoverageReasonCode.GUARD_CONDITION_NOT_SUFFICIENT in by_route["/or-bypass"].reason_codes
    assert by_route["/wrong-flag"].status == CoverageStatus.UNPROTECTED
    assert CoverageReasonCode.WRONG_FLAG_GUARD in by_route["/wrong-flag"].reason_codes


def test_source_snapshot_boundary_checks(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    root = tmp_path / "app"
    root.mkdir()
    (root / "good.py").write_text("@app.get('/health')\ndef h(): return 1\n", encoding="utf-8")
    symlink_path = root / "escape.py"
    symlink_path.symlink_to(outside)

    with pytest.raises(ContractValidationError):
        load_authorized_source_snapshot(
            root_dir=root,
            relative_files=["../outside.py"],
            application_id="app",
            environment="test",
            source_revision="rev",
        )
    with pytest.raises(ContractValidationError):
        load_authorized_source_snapshot(
            root_dir=root,
            relative_files=["escape.py"],
            application_id="app",
            environment="test",
            source_revision="rev",
        )
    with pytest.raises(ContractValidationError):
        build_in_memory_snapshot(
            application_id="app",
            environment="test",
            source_revision="rev",
            files={"good.py": "x = 1\n" * 100},
            limits=SnapshotLimits(max_file_bytes=50),
        )


@pytest.mark.asyncio
async def test_runtime_contradiction_and_endpoint_serializer() -> None:
    src = """
@app.get("/demo/search-v1")
def demo_search():
    states = provider.get_states(("search_v1", "search_v2"), identity=identity)
    if (
        states["search_v1"] is not FeatureState.ENABLED
        or states["search_v2"] is FeatureState.ENABLED
    ):
        return safe_search_fallback()
    return vulnerable_search_documents_for_demo()
"""
    snap = build_in_memory_snapshot(
        application_id="platform_demo_app",
        environment="demo-staging",
        source_revision="demo-rev-0000demo",
        files={"app.py": src},
    )
    ver_fail = VerificationResult(
        verification_id="ver_contra_1",
        incident_id="inc_contra_1",
        test_id="test_sqli_search",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_FAILED,
        passed=False,
        vulnerability_reproduced=True,
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    res = await audit_flag_coverage(
        snap,
        registry=load_route_registry(),
        verification_results=[ver_fail],
        is_fixture=False,
    )
    assert res.evidence_support == CoverageEvidenceSupport.CONTRADICTED
    assert res.findings[0].coverage_status == CoverageStatus.UNKNOWN

    dash = serialize_coverage_dashboard(res)
    assert dash["analysis_scope"] == "bounded_flask_static_analysis"
    endpoint = serialize_flags_coverage_endpoint(
        res,
        observed_features=[
            FeatureState(
                feature_id="fs_search_v1",
                feature_name="search_v1",
                environment="demo-staging",
                enabled=False,
                observation_status=FeatureObservationStatus.OBSERVED,
                observed_at=NOW,
            )
        ],
    )
    assert "covered" in endpoint["routes"][0]
    assert "coverage_status" in endpoint["routes"][0]
    assert "applicability" in endpoint["routes"][0]


@pytest.mark.asyncio
async def test_orchestrator_coverage_audit_and_containment_gate() -> None:
    repo = InMemoryOrchestrationRepository()
    reg = load_route_registry()
    graph = load_dependency_graph()
    orch = IncidentOrchestrator(
        repository=repo,
        route_registry=reg,
        clock=FixedClock(NOW),
        fixture_mode=True,
        containment_strategist=DeterministicContainmentStrategist(
            clock=FixedClock(NOW), registry=reg, fixture_mode=True
        ),
    )
    src = """
@app.get("/search")
def search_route():
    if provider.is_enabled("search_v1"):
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()

@app.get("/demo/direct-search")
def bypass():
    return vulnerable_search_documents_for_demo()
"""
    snap = build_in_memory_snapshot(
        application_id="platform_demo_app",
        environment="demo-staging",
        source_revision="demo-rev-0000demo",
        files={"app.py": src},
    )
    audit_res = await orch.execute_coverage_audit(
        snapshot=snap,
        dependency_graph=graph,
        incident_id="inc_cov_test_1",
    )
    assert audit_res.artifact_reference is not None
    assert audit_res.artifact_reference.artifact_type == ArtifactType.COVERAGE_AUDIT_REPORT

    finding = Finding(
        finding_id="fnd_cov_1",
        incident_id="inc_cov_test_1",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        affected_route="/search",
        affected_component="search_service",
        repository_revision="demo-rev-0000demo",
        environment="demo-staging",
        evidence_ids=["ev_repro_1"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    mapping = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.MATCHED,
        selected_flag="search_v1",
        candidate_flags=["search_v1"],
        affected_route="/search",
        matched_component="search_service",
        registry_version=reg.registry_version,
        mapping_rationale="Exact match.",
        evidence_ids=["ev_repro_1"],
    )
    fs = FeatureState(
        feature_id="fs_search_v1",
        feature_name="search_v1",
        environment="demo-staging",
        enabled=True,
        observation_status=FeatureObservationStatus.OBSERVED,
        observed_at=NOW,
    )
    analysis = await DeterministicContainmentStrategist(
        clock=FixedClock(NOW), registry=reg, fixture_mode=True
    ).analyze_containment(
        finding,
        mapping,
        graph,
        [fs],
        coverage_findings=audit_res.findings,
        application_revision="demo-rev-0000demo",
        environment="demo-staging",
    )
    disable_strats = [
        s for s in analysis.evaluated_strategies if s.strategy_id == "strat_disable_flag"
    ]
    assert disable_strats
    assert ContainmentReasonCode.RESIDUAL_EXPOSURE_UNRESOLVED in disable_strats[0].reason_codes


@pytest.mark.asyncio
async def test_demos_and_evaluator_pass() -> None:
    demos = await run_all_coverage_demos()
    assert len(demos) == 14
    report = await evaluate_coverage_dataset()
    assert report["passed_cases"] == report["total_cases"]
    assert report["false_protected_count"] == 0
