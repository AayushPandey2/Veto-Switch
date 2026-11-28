"""Deterministic offline demonstrations A-N for Phase 06 Feature Flag Coverage Auditing."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from remediation.evidence import IncidentEvidenceReporter
from remediation.reporting.models import EvidenceReportContext, SnapshotBoundary
from shared.config import load_dependency_graph, load_route_registry
from shared.enums import (
    ContainmentReasonCode,
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
from shared.schemas import FeatureState, Finding, MappingResult, VerificationResult

from agent_core.containment_strategist import DeterministicContainmentStrategist
from agent_core.context import FixedClock
from agent_core.coverage.dashboard import (
    serialize_coverage_dashboard,
    serialize_flags_coverage_endpoint,
)
from agent_core.coverage.models import CoverageAuditContext
from agent_core.coverage.source_snapshot import build_in_memory_snapshot
from agent_core.flag_auditor import DeterministicFlagCoverageAuditor
from agent_core.orchestrator import IncidentOrchestrator

NOW = datetime(2026, 11, 28, 12, 0, 0, tzinfo=UTC)

_GUARDED_APP_SRC = '''
@app.get("/search")
def search_route():
    states = provider.get_states(("search_v1", "search_v2"), identity=identity)
    if states["search_v2"] is FeatureState.ENABLED:
        return parameterized_search_documents()
    if states["search_v1"] is FeatureState.ENABLED:
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()

@app.get("/files")
def files_route():
    states = provider.get_states(("files_v1", "files_v2"), identity=identity)
    if states["files_v2"] is FeatureState.ENABLED:
        return safe_read_public_file()
    if states["files_v1"] is FeatureState.ENABLED:
        return vulnerable_read_demo_file_for_demo()
    return safe_files_fallback()

@app.get("/health")
def health():
    return health_response()
'''

_BYPASS_APP_SRC = '''
@app.get("/search")
def search_route():
    if provider.is_enabled("search_v1"):
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()

@app.get("/demo/direct-search")
def direct_search_bypass():
    return vulnerable_search_documents_for_demo()
'''

_LEGACY_EXPORT_SRC = '''
@app.get("/legacy-export")
def legacy_export():
    return legacy_export_records()
'''

_EARLY_RETURN_SRC = '''
@app.get("/demo/search-v1")
def demo_search_v1():
    states = provider.get_states(("search_v1", "search_v2"), identity=identity)
    if (
        states["search_v1"] is not FeatureState.ENABLED
        or states["search_v2"] is FeatureState.ENABLED
    ):
        return safe_search_fallback()
    return vulnerable_search_documents_for_demo()
'''

_LOGGING_ONLY_SRC = '''
@app.get("/search")
def search_logging_only():
    if provider.is_enabled("search_v1"):
        logger.info("search_v1 enabled")
    return vulnerable_search_documents_for_demo()
'''

_POST_SINK_SRC = '''
@app.get("/search")
def search_post_sink():
    res = vulnerable_search_documents_for_demo()
    if provider.is_enabled("search_v1"):
        logger.info("checked too late")
    return res
'''

_WRONG_OR_SRC = '''
@app.get("/search")
def search_wrong_or():
    if provider.is_enabled("search_v1") or provider.is_enabled("other_flag"):
        return vulnerable_search_documents_for_demo()
    return safe_search_fallback()
'''

_DYNAMIC_SRC = '''
@app.get(build_dynamic_route())
def dynamic_handler():
    fn = getattr(service, "search")
    return fn()
'''


async def run_all_coverage_demos() -> list[dict[str, object]]:
    """Run Demos A-N deterministically and return structured summaries."""
    auditor = DeterministicFlagCoverageAuditor(clock=FixedClock(NOW))
    reg = load_route_registry()
    graph = load_dependency_graph()
    results: list[dict[str, object]] = []

    async def _run(
        name: str,
        src: str,
        *,
        use_registry: bool = False,
        use_graph: bool = False,
        observed: list[FeatureState] | None = None,
        verifications: list[VerificationResult] | None = None,
    ) -> CoverageStatus:
        snap = build_in_memory_snapshot(
            application_id="platform_demo_app",
            environment="demo-staging",
            source_revision="demo-rev-0000demo",
            files={"app.py": src},
        )
        ctx = CoverageAuditContext(
            application_id="platform_demo_app",
            environment="demo-staging",
            snapshot=snap,
            registry=reg if use_registry else None,
            dependency_graph=graph if use_graph else None,
            observed_features=list(observed or []),
            verification_results=list(verifications or []),
            is_fixture=True,
        )
        res = await auditor.audit(ctx)
        status = (
            res.route_assessments[0].status
            if res.route_assessments
            else CoverageStatus.UNKNOWN
        )
        results.append(
            {
                "demo": name,
                "sensitive_routes": res.summary.sensitive_routes,
                "protected": res.summary.protected,
                "partially_protected": res.summary.partially_protected,
                "unprotected": res.summary.unprotected,
                "unknown": res.summary.unknown,
                "exempt_routes": res.summary.exempt_routes,
                "first_status": status.value,
            }
        )
        return status

    await _run("Demo A: Guarded search/files + health", _GUARDED_APP_SRC, use_registry=True)
    await _run("Demo B: Alternate entrypoint bypass", _BYPASS_APP_SRC)
    await _run("Demo C: /legacy-export fixture", _LEGACY_EXPORT_SRC)
    await _run("Demo D: Early-return batch-read guard", _EARLY_RETURN_SRC)
    await _run("Demo E: Flag reference only", _LOGGING_ONLY_SRC)
    await _run("Demo F: Guard after sink", _POST_SINK_SRC)
    await _run("Demo G: Insufficient OR guard", _WRONG_OR_SRC)
    await _run("Demo H: Platform batch-read enum identity", _GUARDED_APP_SRC, use_registry=True)
    await _run("Demo I: Dynamic unresolved", _DYNAMIC_SRC)
    await _run(
        "Demo J: Health exemption",
        '@app.get("/health")\ndef h(): return health_response()',
    )
    await _run(
        "Demo K: Registry & files_v2 discrepancy",
        _GUARDED_APP_SRC,
        use_registry=True,
        use_graph=True,
    )

    ver_fail = VerificationResult(
        verification_id="ver_demo_contra",
        incident_id="inc_demo_cov_001",
        test_id="test_sqli_search",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_FAILED,
        passed=False,
        vulnerability_reproduced=True,
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    await _run("Demo L: Runtime contradiction", _EARLY_RETURN_SRC, verifications=[ver_fail])

    orch = IncidentOrchestrator(
        route_registry=reg,
        clock=FixedClock(NOW),
        fixture_mode=True,
        containment_strategist=DeterministicContainmentStrategist(
            clock=FixedClock(NOW), registry=reg, fixture_mode=True
        ),
    )
    snap_bypass = build_in_memory_snapshot(
        application_id="platform_demo_app",
        environment="demo-staging",
        source_revision="demo-rev-0000demo",
        files={"app.py": _BYPASS_APP_SRC},
    )
    audit_m = await orch.execute_coverage_audit(snapshot=snap_bypass, dependency_graph=graph)
    finding = Finding(
        finding_id="fnd_cov_demo_m",
        incident_id="inc_cov_demo_m",
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
        mapping_rationale="Exact route match.",
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
        coverage_findings=audit_m.findings,
        application_revision="demo-rev-0000demo",
        environment="demo-staging",
    )
    has_residual = (
        ContainmentReasonCode.RESIDUAL_EXPOSURE_UNRESOLVED in analysis.reason_codes
        or any(
            ContainmentReasonCode.RESIDUAL_EXPOSURE_UNRESOLVED in s.reason_codes
            for s in analysis.evaluated_strategies
        )
    )
    results.append(
        {
            "demo": "Demo M: Agent 1 bypass containment gate",
            "residual_exposure_flagged": has_residual,
            "proposal_generated": analysis.proposal is not None,
        }
    )

    reporter = IncidentEvidenceReporter()
    rep_ctx = EvidenceReportContext(
        incident_id="inc_cov_demo_n",
        environment="demo-staging",
        accepted_events=[],
        artifact_references=[],
        snapshot_boundary=SnapshotBoundary(
            incident_version=1,
            maximum_event_sequence=0,
            snapshot_captured_at=NOW,
        ),
        coverage_findings=audit_m.findings,
        generation_timestamp=NOW,
        fixture_mode=True,
    )
    report, _ = reporter.build_report_with_details(rep_ctx)
    _ = serialize_coverage_dashboard(audit_m)
    _ = serialize_flags_coverage_endpoint(audit_m, observed_features=[fs])
    results.append(
        {
            "demo": "Demo N: Phase 11 EvidenceReport coverage",
            "coverage_findings_count": len(report.coverage_findings),
        }
    )

    return results


def main() -> None:
    for row in asyncio.run(run_all_coverage_demos()):
        print(row)


if __name__ == "__main__":
    main()
