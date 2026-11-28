"""Category D tests: token budgeting, reduction priority, and mandatory overflow errors."""

from __future__ import annotations

import pytest
from agent_core.intelligence.context_builder import InvestigationContextBuilder
from agent_core.intelligence.investigation_context import (
    InvestigationInputBundle,
    SourceExcerpt,
)
from agent_core.llm.error_mapping import NormalizedLLMError
from agent_core.llm.providers.fixture import FixtureLLMProvider
from agent_core.llm.token_budget import TokenBudgetManager, TokenBudgetPolicy, estimate_tokens
from shared.enums import (
    AIProviderErrorCategory,
    ArtifactType,
    EvidenceProvenance,
    FindingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding


def _make_bundle(
    *, excerpt_chars: int = 200, manifest_entries: int = 0
) -> InvestigationInputBundle:
    finding = Finding(
        finding_id="fnd_b_01",
        incident_id="inc_b_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_b_01"],
        repository_revision="rev_b1",
        environment="staging",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    art = ArtifactReference(
        artifact_id="art_b_01",
        incident_id="inc_b_01",
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash="b" * 64,
        storage_ref="artifacts/inc_b_01/repro.log",
        producer="verifier",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        content_type="text/plain",
        source_revision="rev_b1",
    )
    ex1 = SourceExcerpt(
        file_id="src_primary",
        file_path="app/search_service.py",
        source_revision="rev_b1",
        start_line=1,
        end_line=20,
        code_excerpt="def search(): return 1",
        content_hash="1111" * 8,
        reason_for_inclusion="Primary search_service file",
    )
    ex2 = SourceExcerpt(
        file_id="src_optional",
        file_path="app/other_util.py",
        source_revision="rev_b1",
        start_line=1,
        end_line=50,
        code_excerpt=("x = 'padding_optional'\n" * max(1, excerpt_chars // 22)),
        content_hash="2222" * 8,
        reason_for_inclusion="Secondary unrelated util",
    )
    manifest = {
        "entries": [f"optional_metadata_{i}" * 4 for i in range(manifest_entries)]
    }
    return InvestigationInputBundle(
        finding=finding,
        evidence_artifacts=[art],
        source_excerpts=[ex1, ex2],
        application_manifest_summary=manifest,
    )


@pytest.mark.unit
def test_oversized_optional_context_is_reduced_deterministically() -> None:
    policy = TokenBudgetPolicy(max_input_tokens=2000, reserved_system_tokens=1100)
    builder = InvestigationContextBuilder(budget_policy=policy)
    ctx = builder.build(_make_bundle(excerpt_chars=3500, manifest_entries=30))

    assert ctx.audit is not None
    assert ctx.audit.truncated is True
    assert ctx.audit.post_reduction_tokens <= policy.available_context_tokens()
    assert len(ctx.evidence_references) == 1


@pytest.mark.unit
def test_oversized_mandatory_context_fails_explicitly_never_drops_finding() -> None:
    tiny_policy = TokenBudgetPolicy(max_input_tokens=1400, reserved_system_tokens=1100)
    builder = InvestigationContextBuilder(budget_policy=tiny_policy)
    bundle = _make_bundle(excerpt_chars=50, manifest_entries=0)
    # Force finding + 8 long mandatory evidence references over tiny 144-token budget
    many_arts = [
        bundle.evidence_artifacts[0].model_copy(update={"artifact_id": f"art_m_{i}"})
        for i in range(8)
    ]
    heavy_bundle = bundle.model_copy(
        update={
            "evidence_artifacts": many_arts,
            "finding": bundle.finding.model_copy(
                update={
                    "evidence_ids": [a.artifact_id for a in many_arts],
                    "observed_impact": "Detailed mandatory reproduction trace " * 15,
                }
            ),
        }
    )
    with pytest.raises(NormalizedLLMError) as exc:
        builder.build(heavy_bundle)
    assert exc.value.category == AIProviderErrorCategory.TOKEN_BUDGET_EXCEEDED


@pytest.mark.unit
async def test_token_budget_manager_distinguishes_estimated_vs_measured() -> None:
    mgr = TokenBudgetManager(TokenBudgetPolicy(max_input_tokens=5000))
    est = estimate_tokens("hello world")
    assert est.source == "estimated"

    measured = await mgr.count_text(
        "hello world", provider=FixtureLLMProvider(), model_name="fixture-investigator-v1"
    )
    assert measured.source == "measured"
    assert measured.tokens > 0
