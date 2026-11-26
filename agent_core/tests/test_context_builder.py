"""Category C tests: 10-stage ContextBuilder validation, dedup, redaction & conflicts."""

from __future__ import annotations

import pytest
from agent_core.intelligence.context_builder import InvestigationContextBuilder
from agent_core.intelligence.investigation_context import (
    InvestigationInputBundle,
    SourceExcerpt,
)
from shared.enums import (
    ArtifactType,
    EvidenceProvenance,
    FindingStatus,
    RedactionStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding, VerificationResult


def _base_finding() -> Finding:
    return Finding(
        finding_id="fnd_ctx_01",
        incident_id="inc_ctx_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_repro_01"],
        repository_revision="rev_abc111",
        environment="staging",
        observed_impact=(
            "Exploit observed by operator user@example.com with Bearer synth_tok_1234567890."
        ),
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )


def _artifact(
    art_id: str, incident_id: str = "inc_ctx_01", rev: str = "rev_abc111"
) -> ArtifactReference:
    return ArtifactReference(
        artifact_id=art_id,
        incident_id=incident_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash="a" * 64,
        storage_ref=f"artifacts/{incident_id}/{art_id}.log",
        producer="authorized_verifier",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        content_type="text/plain",
        source_revision=rev,
    )


@pytest.mark.unit
def test_context_builder_excludes_wrong_incident_env_and_revision() -> None:
    finding = _base_finding()
    good_art = _artifact("art_repro_01")
    wrong_inc_art = _artifact("art_wrong_inc", incident_id="inc_OTHER_99")
    wrong_env_art = _artifact("art_wrong_env")
    wrong_rev_ex = SourceExcerpt(
        file_id="src_old",
        file_path="app/search_service.py",
        source_revision="rev_OLD_000",
        start_line=1,
        end_line=5,
        code_excerpt="def old(): pass",
        content_hash="old_hash_12345678",
        reason_for_inclusion="Search handler",
    )

    bundle = InvestigationInputBundle(
        finding=finding,
        evidence_artifacts=[good_art, wrong_inc_art, wrong_env_art],
        artifact_environments={"art_wrong_env": "production"},
        source_excerpts=[wrong_rev_ex],
    )
    ctx = InvestigationContextBuilder().build(bundle)

    included_ids = {a.artifact_id for a in ctx.evidence_references}
    assert included_ids == {"art_repro_01"}
    excluded_reasons = {ex.item_id: ex.reason_code for ex in ctx.excluded_items}
    assert excluded_reasons["art_wrong_inc"] == "INCIDENT_MISMATCH"
    assert excluded_reasons["art_wrong_env"] == "ENVIRONMENT_MISMATCH"
    assert excluded_reasons["src_old"] == "REVISION_MISMATCH"


@pytest.mark.unit
def test_context_builder_redacts_secrets_and_emails_and_deduplicates() -> None:
    finding = _base_finding()
    art = _artifact("art_repro_01")
    dup_art = _artifact("art_repro_01")
    ex1 = SourceExcerpt(
        file_id="src_1",
        file_path="app/search_service.py",
        source_revision="rev_abc111",
        start_line=1,
        end_line=4,
        code_excerpt="# api_key=sk-secret-abc1234567890\nreturn db.exec(q)",
        content_hash="1111" * 8,
        reason_for_inclusion="Primary",
    )
    ex2_dup = ex1.model_copy(update={"file_id": "src_1_dup"})

    bundle = InvestigationInputBundle(
        finding=finding,
        evidence_artifacts=[art, dup_art],
        source_excerpts=[ex1, ex2_dup],
    )
    ctx = InvestigationContextBuilder().build(bundle)

    assert len(ctx.evidence_references) == 1
    assert len(ctx.bounded_source_excerpts) == 1
    assert "sk-secret-abc1234567890" not in ctx.bounded_source_excerpts[0].code_excerpt
    assert "user@example.com" not in (ctx.finding.observed_impact or "")
    assert "synth_tok_1234567890" not in (ctx.finding.observed_impact or "")
    assert ctx.audit is not None
    assert ctx.audit.redaction_status == RedactionStatus.REDACTED
    assert len(ctx.context_hash) == 64


@pytest.mark.unit
def test_context_builder_preserves_contradictory_verifications() -> None:
    finding = _base_finding()
    v1 = VerificationResult(
        verification_id="ver_a",
        incident_id="inc_ctx_01",
        test_id="t_sqli",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
        tested_revision="rev_abc111",
        artifact_ids=["art_repro_01"],
    )
    v2 = VerificationResult(
        verification_id="ver_b",
        incident_id="inc_ctx_01",
        test_id="t_sqli_2",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_FAILED,
        passed=False,
        vulnerability_reproduced=False,
        tested_revision="rev_abc111",
        artifact_ids=["art_repro_01"],
    )
    bundle = InvestigationInputBundle(
        finding=finding,
        evidence_artifacts=[_artifact("art_repro_01")],
        verification_results=[v1, v2],
    )
    ctx = InvestigationContextBuilder().build(bundle)
    assert ctx.verification_summary.conflicting_outcomes is True
    assert ctx.verification_summary.reproduction_outcome == "inconclusive"
    assert any("Conflicting verification outcomes" in lim for lim in ctx.known_limitations)
