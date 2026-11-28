"""Category G tests: Investigator workflows across categories, gaps, review, and UI payload."""

from __future__ import annotations

import pytest
from agent_core.intelligence.investigation_context import (
    AdvisoryContextItem,
    DependencyMetadataItem,
    InvestigationInputBundle,
    SourceExcerpt,
)
from agent_core.investigator import Investigator
from agent_core.llm.providers.fixture import FixtureBehaviorMode
from agent_core.llm_client import build_default_gateway
from shared.enums import (
    ArtifactType,
    EvidenceProvenance,
    EvidenceSupportLevel,
    FindingStatus,
    InvestigationStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding, VerificationResult


def _bundle(
    *,
    incident_id: str = "inc_inv_01",
    category: VulnerabilityCategory = VulnerabilityCategory.SQL_INJECTION,
    status: FindingStatus = FindingStatus.REPRODUCED,
    with_source: bool = True,
    repro_outcome: bool | None = True,
    with_ver: bool = True,
    conflicting_ver: bool = False,
) -> InvestigationInputBundle:
    finding = Finding(
        finding_id=f"fnd_{incident_id}",
        incident_id=incident_id,
        category=category,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=status,
        evidence_ids=["art_inv_01"],
        cve_ids=["CVE-2024-7777"] if category == VulnerabilityCategory.DEPENDENCY_CVE else [],
        repository_revision="rev_inv_01",
        environment="staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    art = ArtifactReference(
        artifact_id="art_inv_01",
        incident_id=incident_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash="d" * 64,
        storage_ref=f"artifacts/{incident_id}/repro.log",
        producer="verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        source_revision="rev_inv_01",
    )
    vers: list[VerificationResult] = []
    if with_ver:
        vers.append(
            VerificationResult(
                verification_id="ver_inv_1",
                incident_id=incident_id,
                test_id="t_1",
                phase=VerificationPhase.BEFORE_CONTAINMENT,
                execution_status=(
                    TestExecutionStatus.TEST_PASSED
                    if repro_outcome
                    else TestExecutionStatus.TEST_FAILED
                ),
                passed=bool(repro_outcome),
                vulnerability_reproduced=repro_outcome,
                tested_revision="rev_inv_01",
                artifact_ids=["art_inv_01"],
                provenance=EvidenceProvenance.REFERENCE_FIXTURE,
            )
        )
        if conflicting_ver:
            vers.append(
                VerificationResult(
                    verification_id="ver_inv_2",
                    incident_id=incident_id,
                    test_id="t_2",
                    phase=VerificationPhase.BEFORE_CONTAINMENT,
                    execution_status=TestExecutionStatus.TEST_FAILED,
                    passed=False,
                    vulnerability_reproduced=False,
                    tested_revision="rev_inv_01",
                    artifact_ids=["art_inv_01"],
                    provenance=EvidenceProvenance.REFERENCE_FIXTURE,
                )
            )
    excerpts = (
        [
            SourceExcerpt(
                file_id="src_inv_01",
                file_path="app/search_service.py",
                source_revision="rev_inv_01",
                start_line=1,
                end_line=10,
                code_excerpt="def search(q): return db.execute(f'SELECT * FROM t WHERE x={q}')",
                content_hash="hash_inv_01010101",
                reason_for_inclusion="Handler excerpt",
            )
        ]
        if with_source
        else []
    )
    deps = (
        [
            DependencyMetadataItem(
                dependency_name="search-pkg",
                installed_version="1.0.0",
                relevant_component="search_service",
                advisory_references=["CVE-2024-7777"],
            )
        ]
        if category == VulnerabilityCategory.DEPENDENCY_CVE
        else []
    )
    advs = (
        [
            AdvisoryContextItem(
                advisory_id="adv_inv_1",
                cve_ids=["CVE-2024-7777"],
                package_name="search-pkg",
                summary="Version match advisory.",
            )
        ]
        if category == VulnerabilityCategory.DEPENDENCY_CVE
        else []
    )
    return InvestigationInputBundle(
        finding=finding,
        evidence_artifacts=[art],
        verification_results=vers,
        source_excerpts=excerpts,
        dependencies=deps,
        advisories=advs,
    )


@pytest.mark.unit
async def test_investigator_reproduced_sqli_and_dashboard_payload() -> None:
    inv = Investigator(llm_gateway=build_default_gateway(fixture_mode=FixtureBehaviorMode.VALID))
    res = await inv.investigate_bundle(_bundle())

    assert res.summary.investigation_status == InvestigationStatus.COMPLETED
    assert res.summary.evidence_support_level == EvidenceSupportLevel.HIGH_EVIDENCE_SUPPORT
    assert res.summary.recommended_next_action == "request_feature_mapping"
    assert res.grounding_report.overall_valid is True

    dash = res.to_dashboard_payload()
    assert dash["incident_id"] == "inc_inv_01"
    assert dash["investigation"]["source"] == "synthetic_fixture"
    assert dash["validation"]["reference_checks_passed"] is True
    assert dash["validation"]["semantic_review_required"] is True
    assert dash["investigation"]["verified_facts"][0]["badge"] == "verified_fact"
    assert dash["investigation"]["potential_impacts"][0]["badge"] in {
        "potential_impact",
        "verified_impact",
    }


@pytest.mark.unit
async def test_investigator_suspected_dependency_cve_and_path_traversal() -> None:
    inv = Investigator(llm_gateway=build_default_gateway())

    pt_res = await inv.investigate_bundle(
        _bundle(
            incident_id="inc_pt_01",
            category=VulnerabilityCategory.PATH_TRAVERSAL,
            status=FindingStatus.REPRODUCED,
        )
    )
    assert pt_res.summary.recommended_next_action == "request_feature_mapping"

    cve_res = await inv.investigate_bundle(
        _bundle(
            incident_id="inc_cve_01",
            category=VulnerabilityCategory.DEPENDENCY_CVE,
            status=FindingStatus.SUSPECTED,
            with_source=False,
            with_ver=False,
        )
    )
    assert cve_res.summary.finding_status == FindingStatus.SUSPECTED
    assert cve_res.summary.recommended_next_action == "request_verification"
    assert "confirmed_reproduction_verification" in cve_res.summary.missing_evidence


@pytest.mark.unit
async def test_investigator_missing_source_contradictions_and_unknown_category() -> None:
    inv = Investigator(llm_gateway=build_default_gateway())

    no_src = await inv.investigate_bundle(_bundle(incident_id="inc_ns", with_source=False))
    assert no_src.summary.investigation_status == InvestigationStatus.PARTIAL
    assert "authorized_source_excerpt" in no_src.summary.missing_evidence

    contra = await inv.investigate_bundle(_bundle(incident_id="inc_con", conflicting_ver=True))
    assert contra.summary.requires_manual_review is True
    assert contra.summary.recommended_next_action == "require_manual_review"
    assert contra.summary.investigation_status == InvestigationStatus.MANUAL_REVIEW_REQUIRED

    other = await inv.investigate_bundle(
        _bundle(
            incident_id="inc_oth",
            category=VulnerabilityCategory.OTHER,
            status=FindingStatus.SUSPECTED,
            with_ver=False,
            with_source=False,
        )
    )
    assert other.summary.requires_manual_review is True
    assert other.summary.recommended_next_action == "require_manual_review"
