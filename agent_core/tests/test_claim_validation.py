"""Category F tests (part 2): deterministic factual contradiction & hallucination checks."""

from __future__ import annotations

import pytest
from agent_core.intelligence.claim_validator import (
    detect_factual_contradictions,
    detect_hallucinated_identifiers,
    validate_single_claim,
)
from agent_core.intelligence.context_builder import InvestigationContextBuilder
from agent_core.intelligence.evidence_grounding import validate_investigation_grounding
from agent_core.intelligence.investigation_context import (
    AdvisoryContextItem,
    InvestigationContext,
    InvestigationInputBundle,
)
from shared.enums import (
    ArtifactType,
    ClaimCategory,
    EvidenceProvenance,
    FindingStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding, GroundedClaim, VerificationResult


def _suspected_context(
    *,
    category: VulnerabilityCategory = VulnerabilityCategory.SQL_INJECTION,
    cve_ids: list[str] | None = None,
) -> InvestigationContext:
    finding = Finding(
        finding_id="fnd_c_01",
        incident_id="inc_c_01",
        category=category,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.SUSPECTED,
        evidence_ids=["art_c_01"],
        cve_ids=cve_ids or [],
        repository_revision="rev_c1",
        environment="staging",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    art = ArtifactReference(
        artifact_id="art_c_01",
        incident_id="inc_c_01",
        artifact_type=ArtifactType.SCANNER_REPORT,
        content_hash="c" * 64,
        storage_ref="artifacts/inc_c_01/scan.json",
        producer="scanner",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        content_type="application/json",
        source_revision="rev_c1",
    )
    ver = VerificationResult(
        verification_id="ver_c_01",
        incident_id="inc_c_01",
        test_id="t_c_01",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.NOT_RUN,
        passed=None,
        vulnerability_reproduced=None,
        tested_revision="rev_c1",
        artifact_ids=["art_c_01"],
    )
    advs = (
        [
            AdvisoryContextItem(
                advisory_id="adv_1",
                cve_ids=cve_ids or [],
                package_name="pkg",
                summary="Advisory version match.",
            )
        ]
        if cve_ids
        else []
    )
    return InvestigationContextBuilder().build(
        InvestigationInputBundle(
            finding=finding,
            evidence_artifacts=[art],
            verification_results=[ver],
            advisories=advs,
        )
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_statement",
    [
        "The baseline security test passed with zero failures.",
        "Exploitation was reproduced against staging.",
        "Every database route and all endpoints are compromised.",
        "The source repair has been deployed and the incident is contained.",
    ],
)
def test_deterministic_contradictions_caught(bad_statement: str) -> None:
    ctx = _suspected_context()
    claim = GroundedClaim(
        claim_id="clm_bad",
        statement=bad_statement,
        classification=ClaimCategory.OBSERVED,
        evidence_ids=["art_c_01"],
    )
    contradictions = detect_factual_contradictions(claim, context=ctx)
    assert len(contradictions) >= 1


@pytest.mark.unit
def test_cve_advisory_cannot_claim_exploited_without_reproduction() -> None:
    ctx = _suspected_context(
        category=VulnerabilityCategory.DEPENDENCY_CVE, cve_ids=["CVE-2024-5555"]
    )
    claim = GroundedClaim(
        claim_id="clm_cve_bad",
        statement="CVE-2024-5555 was actively exploited in production runtime.",
        classification=ClaimCategory.OBSERVED,
        evidence_ids=["art_c_01"],
    )
    contradictions = detect_factual_contradictions(claim, context=ctx)
    assert any("Dependency CVE" in c or "reproduction" in c for c in contradictions)


@pytest.mark.unit
def test_hallucinated_cve_and_file_path_detected() -> None:
    ctx = _suspected_context(
        category=VulnerabilityCategory.DEPENDENCY_CVE, cve_ids=["CVE-2024-5555"]
    )
    invented = detect_hallucinated_identifiers(
        "Found CVE-2024-9999 inside app/made_up_secret_file.py.", context=ctx
    )
    assert "invented_cve:CVE-2024-9999" in invented
    assert "unverified_file_path:app/made_up_secret_file.py" in invented


@pytest.mark.unit
def test_unsupported_observed_claim_without_evidence_rejected() -> None:
    ctx = _suspected_context()
    claim = GroundedClaim(
        claim_id="clm_no_ev",
        statement="Scanner ran on /search.",
        classification=ClaimCategory.OBSERVED,
        evidence_ids=[],
    )
    _, _, unsup, _, _ = validate_single_claim(claim, context=ctx)
    assert "clm_no_ev" in unsup


@pytest.mark.unit
def test_inferred_interpretations_require_semantic_review() -> None:
    ctx = _suspected_context()
    interp = GroundedClaim(
        claim_id="clm_inf",
        statement="Input validation pattern may allow query manipulation.",
        classification=ClaimCategory.INFERRED,
        evidence_ids=["art_c_01"],
    )
    _, interps, report = validate_investigation_grounding(
        claims=[],
        interpretations=[interp],
        top_level_evidence_ids=["art_c_01"],
        executive_summary="Summary",
        technical_explanation="Explanation",
        affected_components=["search_service"],
        affected_route="/search",
        context=ctx,
    )
    assert report.overall_valid is True
    assert report.semantic_review_required is True
    assert "clm_inf" in report.claims_requiring_review
    assert interps[0].validation_status.value == "unverified_interpretation"
