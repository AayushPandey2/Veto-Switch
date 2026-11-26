"""Category K tests: observability, correlation, unknown tokens, cost & redaction."""

from __future__ import annotations

import logging

import pytest
from agent_core.intelligence.investigation_context import (
    InvestigationInputBundle,
    SourceExcerpt,
)
from agent_core.investigator import Investigator
from agent_core.llm.gateway import LLMGateway
from agent_core.llm.observability import (
    AIMetricsCollector,
    ModelPricingConfig,
    estimate_execution_cost,
)
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.providers.fixture import FixtureBehaviorMode, FixtureLLMProvider
from agent_core.llm.routing import ModelRouter
from shared.enums import (
    AITaskType,
    ArtifactType,
    EvidenceProvenance,
    FindingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, Finding


@pytest.mark.unit
async def test_observability_records_hashes_tokens_and_unknown_tokens_remain_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="killswitch.ai.observability")
    metrics = AIMetricsCollector()
    fix = FixtureLLMProvider(default_mode=FixtureBehaviorMode.MISSING_USAGE)
    reg = ProviderRegistry()
    reg.register(fix)
    gw = LLMGateway(registry=reg, router=ModelRouter(registry=reg), metrics=metrics)
    inv = Investigator(llm_gateway=gw, metrics=metrics)

    finding = Finding(
        finding_id="fnd_obs_01",
        incident_id="inc_obs_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.SUSPECTED,
        evidence_ids=["art_obs_01"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    art = ArtifactReference(
        artifact_id="art_obs_01",
        incident_id="inc_obs_01",
        artifact_type=ArtifactType.SCANNER_REPORT,
        content_hash="1" * 64,
        storage_ref="artifacts/inc_obs_01/scan.json",
        producer="scanner",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="application/json",
    )
    secret_code = "SECRET_SOURCE_CODE_MARKER = 'never_log_full_source'\napi_key = 'sk-synth-999'"
    ex = SourceExcerpt(
        file_id="src_obs",
        file_path="app/search.py",
        start_line=1,
        end_line=3,
        code_excerpt=secret_code,
        content_hash="hash_obs_01010101",
        reason_for_inclusion="Test",
    )
    res = await inv.investigate_bundle(
        InvestigationInputBundle(finding=finding, evidence_artifacts=[art], source_excerpts=[ex]),
        correlation_id="corr_obs_1234",
    )

    assert res.execution_record is not None
    assert res.execution_record.correlation_id == "corr_obs_1234"
    assert res.execution_record.prompt_version == "1.0.0"
    assert res.execution_record.prompt_hash is not None
    assert res.execution_record.context_hash is not None
    assert res.execution_record.input_tokens is None
    assert res.execution_record.output_tokens is None
    assert res.execution_record.cost_status == "unknown"
    assert res.execution_record.cost_usd is None
    assert metrics.unknown_token_responses == 1

    # Ensure logs NEVER dumped raw source excerpt marker or secret key
    joined_logs = "\n".join(rec.message for rec in caplog.records)
    assert "SECRET_SOURCE_CODE_MARKER" not in joined_logs
    assert "sk-synth-999" not in joined_logs
    assert AITaskType.INVESTIGATION.value in str(metrics.snapshot() or "") or (
        metrics.successful_llm_investigations == 1
    )


@pytest.mark.unit
def test_cost_estimation_requires_explicit_pricing_config() -> None:
    usd_none, status_none = estimate_execution_cost(
        provider="gemini",
        model_name="gemini-2.5-flash",
        input_tokens=1000,
        output_tokens=500,
        pricing_table=None,
    )
    assert usd_none is None
    assert status_none == "unknown"

    table = {
        ("gemini", "gemini-2.5-flash"): ModelPricingConfig(
            provider="gemini",
            model_name="gemini-2.5-flash",
            input_usd_per_1k=0.001,
            output_usd_per_1k=0.002,
        )
    }
    usd_est, status_est = estimate_execution_cost(
        provider="gemini",
        model_name="gemini-2.5-flash",
        input_tokens=2000,
        output_tokens=1000,
        pricing_table=table,
    )
    assert status_est == "estimated"
    assert usd_est == pytest.approx(0.004)
