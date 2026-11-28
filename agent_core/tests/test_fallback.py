"""Category J tests: deterministic fallback triggers, status preservation & honesty."""

from __future__ import annotations

import pytest
from agent_core.intelligence.investigation_context import InvestigationInputBundle
from agent_core.investigator import Investigator
from agent_core.llm.providers.fixture import FixtureBehaviorMode
from agent_core.llm_client import build_default_gateway
from shared.enums import (
    ArtifactType,
    EvidenceProvenance,
    FindingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding


def _suspected_bundle() -> InvestigationInputBundle:
    finding = Finding(
        finding_id="fnd_fb_01",
        incident_id="inc_fb_01",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        affected_route="/download",
        affected_component="file_exporter",
        severity=VulnerabilitySeverity.MEDIUM,
        status=FindingStatus.SUSPECTED,
        evidence_ids=["art_fb_01"],
        repository_revision="rev_fb_01",
        environment="staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    art = ArtifactReference(
        artifact_id="art_fb_01",
        incident_id="inc_fb_01",
        artifact_type=ArtifactType.SCANNER_REPORT,
        content_hash="f" * 64,
        storage_ref="artifacts/inc_fb_01/scan.json",
        producer="scanner",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="application/json",
        source_revision="rev_fb_01",
    )
    return InvestigationInputBundle(finding=finding, evidence_artifacts=[art])


@pytest.mark.unit
@pytest.mark.parametrize(
    "mode",
    [
        FixtureBehaviorMode.AUTH_ERROR,
        FixtureBehaviorMode.TIMEOUT,
        FixtureBehaviorMode.RATE_LIMIT,
        FixtureBehaviorMode.UNAVAILABLE,
        FixtureBehaviorMode.MALFORMED_JSON,
        FixtureBehaviorMode.SCHEMA_INVALID,
        FixtureBehaviorMode.HALLUCINATED_EVIDENCE,
        FixtureBehaviorMode.CONTRADICTORY_CLAIM,
    ],
)
async def test_fallback_activates_on_failures_and_preserves_invariants(
    mode: FixtureBehaviorMode,
) -> None:
    gw = build_default_gateway(fixture_mode=mode)
    inv = Investigator(llm_gateway=gw)
    res = await inv.investigate_bundle(_suspected_bundle())

    assert res.summary.fallback_used is True
    assert res.summary.fallback_reason is not None
    assert res.summary.reasoning_source == EvidenceProvenance.DETERMINISTIC_FALLBACK
    assert res.summary.finding_status == FindingStatus.SUSPECTED
    assert "No authorized source-code excerpt was supplied" in res.summary.technical_explanation
    if mode == FixtureBehaviorMode.CONTRADICTORY_CLAIM:
        assert res.summary.recommended_next_action == "require_manual_review"
    else:
        assert res.summary.recommended_next_action == "request_verification"
    assert res.grounding_report.unknown_references == []


@pytest.mark.unit
async def test_fallback_works_with_zero_gateway_and_no_fabricated_root_cause() -> None:
    inv = Investigator(llm_gateway=None, fallback_enabled=True)
    res = await inv.investigate_bundle(_suspected_bundle())
    assert res.summary.fallback_used is True
    assert res.summary.fallback_reason == "no_llm_gateway_configured"
    assert res.summary.model_metadata is not None
    assert res.summary.model_metadata.fallback_used is True
    assert res.summary.model_metadata.synthetic_origin is False
