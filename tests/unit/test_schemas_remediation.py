"""Unit tests for remediation, rollout, telemetry, rollback, coverage, and report schemas."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from shared.enums import (
    CoverageStatus,
    DeploymentStatus,
    EvidenceCompleteness,
    EvidenceProvenance,
    IncidentState,
    PatchOrigin,
    RolloutDecisionType,
    TestExecutionStatus,
)
from shared.exceptions import PatchValidationError
from shared.schemas import (
    CoverageFinding,
    DeploymentEvidence,
    EvidenceReport,
    IndividualTestOutcome,
    LatencyStats,
    MetricSnapshot,
    PatchProposal,
    PatchTestResult,
    RollbackProposal,
    RolloutDecision,
    RolloutGuardrailConfig,
    RolloutPlan,
    RolloutStage,
)


def _guardrails() -> RolloutGuardrailConfig:
    return RolloutGuardrailConfig(
        max_error_rate=0.02,
        max_error_rate_increase_pp=1.0,
        max_p95_latency_increase_percent=20.0,
    )


def _stage(stage_id: str, pct: int) -> RolloutStage:
    return RolloutStage(
        stage_id=stage_id,
        exposure_percentage=pct,
        required_metrics=["error_rate", "p95_ms"],
        minimum_observation_window_seconds=30,
        minimum_request_count=100,
        guardrails=_guardrails(),
    )


@pytest.mark.unit
def test_rollout_stage_percentages_and_ordering_validation() -> None:
    """Scenarios 7 & 11: Invalid rollout percentages and non-increasing stages are rejected."""
    with pytest.raises(ValidationError):
        _stage("rstage_bad", 150)

    with pytest.raises(ValidationError):
        _stage("rstage_neg", -5)

    plan = RolloutPlan(
        plan_id="rplan_0001",
        incident_id="inc_0001",
        target_feature="search_v2",
        environment="demo-staging",
        target_implementation_revision="rev_patched_1",
        stages=[_stage("rstage_1", 5), _stage("rstage_2", 25)],
        guardrails=_guardrails(),
    )
    assert len(plan.stages) == 2

    with pytest.raises(ValidationError):
        RolloutPlan(
            plan_id="rplan_0002",
            incident_id="inc_0001",
            target_feature="search_v2",
            environment="demo-staging",
            target_implementation_revision="rev_patched_1",
            stages=[_stage("rstage_1", 25), _stage("rstage_2", 25)],
            guardrails=_guardrails(),
        )


@pytest.mark.unit
def test_metric_snapshot_validation_and_synthetic_provenance() -> None:
    """Scenarios 8, 9, 10, 15: Negative metrics, failed>total, unknown!=0, synthetic provenance."""
    unknown_snap = MetricSnapshot(
        snapshot_id="met_0001",
        incident_id="inc_0001",
        environment="demo-staging",
        feature_id="search_v2",
        observation_window_seconds=30,
        request_count=None,
        failed_request_count=None,
        error_rate=None,
        latency_ms=LatencyStats(p50_ms=None, p95_ms=None, p99_ms=None),
        provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
    )
    assert unknown_snap.request_count is None
    assert unknown_snap.error_rate is None
    assert unknown_snap.provenance == EvidenceProvenance.SYNTHETIC_TELEMETRY

    with pytest.raises(ValidationError):
        MetricSnapshot(
            snapshot_id="met_neg",
            incident_id="inc_0001",
            environment="demo-staging",
            feature_id="search_v2",
            observation_window_seconds=30,
            request_count=-1,
            provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        )

    with pytest.raises(ValidationError):
        MetricSnapshot(
            snapshot_id="met_gt",
            incident_id="inc_0001",
            environment="demo-staging",
            feature_id="search_v2",
            observation_window_seconds=30,
            request_count=10,
            failed_request_count=11,
            provenance=EvidenceProvenance.SYNTHETIC_TELEMETRY,
        )


@pytest.mark.unit
def test_patch_proposal_allowlist_and_revision_mismatch_detection() -> None:
    """Scenario 17: Path traversal rejected; revision mismatch and functional failure detected."""
    with pytest.raises((ValidationError, PatchValidationError)):
        PatchProposal(
            patch_id="pat_0001",
            incident_id="inc_0001",
            finding_id="fnd_0001",
            source_revision="rev_001",
            candidate_artifact_id="art_0001",
            candidate_content_hash="a" * 64,
            unified_diff="--- a/app/search.py\n+++ b/app/search.py\n",
            allowed_files=["app/search.py"],
            touched_files=["../etc/passwd"],
            technical_rationale="Bad path traversal",
            required_tests=["test_sqli"],
            patch_origin=PatchOrigin.LLM_CANDIDATE,
        )

    mismatch = PatchTestResult(
        test_run_id="trun_0001",
        patch_id="pat_0001",
        incident_id="inc_0001",
        expected_source_revision="rev_expected",
        tested_source_revision="rev_stale",
        tested_candidate_hash="a" * 64,
        individual_outcomes=[
            IndividualTestOutcome(
                test_name="test_sqli",
                category="security",
                status=TestExecutionStatus.TEST_PASSED,
            )
        ],
        overall_status=TestExecutionStatus.TEST_PASSED,
        started_at=datetime(2026, 11, 26, 0, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 11, 26, 0, 0, 5, tzinfo=UTC),
    )
    assert mismatch.has_revision_mismatch is True
    assert mismatch.is_trusted_pass is False

    with pytest.raises(ValidationError):
        PatchTestResult(
            test_run_id="trun_0002",
            patch_id="pat_0001",
            incident_id="inc_0001",
            expected_source_revision="rev_expected",
            tested_source_revision="rev_expected",
            tested_candidate_hash="a" * 64,
            individual_outcomes=[
                IndividualTestOutcome(
                    test_name="test_sqli",
                    category="security",
                    status=TestExecutionStatus.TEST_PASSED,
                ),
                IndividualTestOutcome(
                    test_name="test_functional",
                    category="functional",
                    status=TestExecutionStatus.TEST_FAILED,
                ),
            ],
            overall_status=TestExecutionStatus.TEST_PASSED,
            started_at=datetime(2026, 11, 26, 0, 0, 0, tzinfo=UTC),
            completed_at=datetime(2026, 11, 26, 0, 0, 5, tzinfo=UTC),
        )


@pytest.mark.unit
def test_deployment_rollout_decision_rollback_coverage_and_report_invariants() -> None:
    with pytest.raises(ValidationError):
        DeploymentEvidence(
            deployment_id="dep_0001",
            environment="demo-staging",
            implementation_id="search_v2",
            feature_name="search_v2",
            source_revision="rev_002",
            implementation_hash="b" * 64,
            deployment_status=DeploymentStatus.MISSING,
            addressable=True,
        )

    with pytest.raises(ValidationError):
        RolloutDecision(
            decision_id="rdec_0001",
            plan_id="rplan_0001",
            incident_id="inc_0001",
            current_stage_id="rstage_1",
            proposed_next_stage_id="rstage_2",
            decision_type=RolloutDecisionType.ADVANCE,
            missing_evidence=["baseline_p95_latency_ms"],
            explanation="Invalid advance with missing evidence",
        )

    with pytest.raises(ValidationError):
        RollbackProposal(
            proposal_id="rbk_0001",
            incident_id="inc_0001",
            target_environment="demo-staging",
            target_feature="search_v2",
            last_verified_safe_state_known=False,
            last_verified_safe_state=False,
            proposed_state=False,
            triggering_evidence_ids=["art_0001"],
            rollback_rationale="Cannot set last_verified_safe_state when unknown",
        )

    cov = CoverageFinding(
        coverage_finding_id="cov_0001",
        route="/legacy-export",
        component="legacy_export_service",
        coverage_status=CoverageStatus.UNPROTECTED,
        explanation="No feature flag guards /legacy-export.",
        recommended_action="Add emergency kill-switch flag.",
    )
    assert cov.coverage_status == CoverageStatus.UNPROTECTED

    with pytest.raises(ValidationError):
        EvidenceReport(
            report_id="rep_0001",
            incident_id="inc_0001",
            incident_status=IncidentState.CONTAINED,
            missing_evidence=["patch_test_result"],
            completeness=EvidenceCompleteness.COMPLETE,
        )
