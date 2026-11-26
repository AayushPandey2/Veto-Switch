"""Category F tests (part 1): claim reference existence, cross-incident, env/rev mismatch."""

from __future__ import annotations

import pytest
from agent_core.intelligence.context_builder import InvestigationContextBuilder
from agent_core.intelligence.evidence_grounding import validate_investigation_grounding
from agent_core.intelligence.investigation_context import InvestigationInputBundle
from shared.enums import (
    ArtifactType,
    ClaimCategory,
    EvidenceProvenance,
    FindingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding, GroundedClaim


def _context_with_mismatches() -> InvestigationInputBundle:
    finding = Finding(
        finding_id="fnd_g_01",
        incident_id="inc_g_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.SUSPECTED,
        evidence_ids=["art_valid_01"],
        repository_revision="rev_curr_01",
        environment="staging",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    valid_art = ArtifactReference(
        artifact_id="art_valid_01",
        incident_id="inc_g_01",
        artifact_type=ArtifactType.SCANNER_REPORT,
        content_hash="a" * 64,
        storage_ref="artifacts/inc_g_01/scan.json",
        producer="scanner",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        content_type="application/json",
        source_revision="rev_curr_01",
    )
    foreign_art = valid_art.model_copy(
        update={"artifact_id": "art_foreign_99", "incident_id": "inc_OTHER"}
    )
    return InvestigationInputBundle(
        finding=finding,
        evidence_artifacts=[valid_art, foreign_art],
    )


@pytest.mark.unit
def test_valid_reference_passes_grounding() -> None:
    ctx = InvestigationContextBuilder().build(_context_with_mismatches())
    claim = GroundedClaim(
        claim_id="clm_ok",
        statement="Static scanner reported finding in staging.",
        classification=ClaimCategory.OBSERVED,
        evidence_ids=["art_valid_01"],
        environment="staging",
        source_revision="rev_curr_01",
    )
    facts, _, report = validate_investigation_grounding(
        claims=[claim],
        interpretations=[],
        top_level_evidence_ids=["art_valid_01"],
        executive_summary="Summary",
        technical_explanation="Explanation",
        affected_components=["search_service"],
        affected_route="/search",
        context=ctx,
    )
    assert report.overall_valid is True
    assert report.reference_checks_passed is True
    assert facts[0].claim_id == "clm_ok"


@pytest.mark.unit
def test_invented_and_cross_incident_references_are_rejected() -> None:
    ctx = InvestigationContextBuilder().build(_context_with_mismatches())
    claim = GroundedClaim(
        claim_id="clm_bad",
        statement="Claim citing nonexistent and foreign artifacts.",
        classification=ClaimCategory.OBSERVED,
        evidence_ids=["art_invented_000", "art_foreign_99"],
    )
    _, _, report = validate_investigation_grounding(
        claims=[claim],
        interpretations=[],
        top_level_evidence_ids=["art_invented_000"],
        executive_summary="Summary",
        technical_explanation="Explanation",
        affected_components=["search_service"],
        affected_route="/search",
        context=ctx,
    )
    assert report.overall_valid is False
    assert report.reference_checks_passed is False
    assert any("art_invented_000" in u for u in report.unknown_references)
    assert any("art_foreign_99" in u for u in report.unknown_references)


@pytest.mark.unit
def test_claim_with_wrong_environment_or_revision_is_flagged_as_contradiction() -> None:
    ctx = InvestigationContextBuilder().build(_context_with_mismatches())
    claim = GroundedClaim(
        claim_id="clm_env_mismatch",
        statement="Finding observed.",
        classification=ClaimCategory.OBSERVED,
        evidence_ids=["art_valid_01"],
        environment="production",
        source_revision="rev_different_99",
    )
    _, _, report = validate_investigation_grounding(
        claims=[claim],
        interpretations=[],
        top_level_evidence_ids=["art_valid_01"],
        executive_summary="Summary",
        technical_explanation="Explanation",
        affected_components=["search_service"],
        affected_route="/search",
        context=ctx,
    )
    assert report.overall_valid is False
    assert report.contradiction_checks_passed is False
    assert len(report.direct_factual_contradictions) == 2
