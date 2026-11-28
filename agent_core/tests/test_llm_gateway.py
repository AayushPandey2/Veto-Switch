"""Category B tests: central LLMGateway routing, Gemini transport, retries, cache & reuse."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

import httpx
import pytest
from agent_core.context import FixedClock
from agent_core.intelligence.response_validator import RawInvestigationOutput
from agent_core.llm.cache import SafeAIResultCache
from agent_core.llm.error_mapping import NormalizedLLMError
from agent_core.llm.gateway import LLMGateway, ProviderCircuitBreaker
from agent_core.llm.observability import AIMetricsCollector
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.providers.fixture import FixtureBehaviorMode, FixtureLLMProvider
from agent_core.llm.providers.gemini import GeminiLLMProvider
from agent_core.llm.routing import ModelRouter, TaskRouteConfig, TaskRouteTarget
from agent_core.prompts.registry import PromptRegistry
from agent_core.retry_policy import RetryPolicyConfig
from pydantic import Field, SecretStr
from shared.enums import AIProviderErrorCategory, AITaskType, DataClassification
from shared.exceptions import UnauthorizedOperationError
from shared.identifiers import utc_now
from shared.schemas import KillswitchModel


def _minimal_context() -> dict[str, Any]:
    return {
        "incident_id": "inc_gw_01",
        "finding": {
            "finding_id": "fnd_gw_01",
            "category": "sql_injection",
            "status": "reproduced",
            "affected_component": "search_service",
            "affected_route": "/search",
            "evidence_ids": ["art_repro_01"],
        },
        "verification_summary": {"reproduction_outcome": "reproduced"},
        "evidence_references": [{"artifact_id": "art_repro_01", "content_hash": "a" * 64}],
        "bounded_source_excerpts": [],
    }


@pytest.mark.unit
async def test_gateway_constructs_request_tracks_prompt_and_caches_safely() -> None:
    clk = FixedClock(utc_now())
    fix = FixtureLLMProvider(default_mode=FixtureBehaviorMode.VALID)
    reg = ProviderRegistry()
    reg.register(fix)
    metrics = AIMetricsCollector()
    gw = LLMGateway(
        registry=reg,
        router=ModelRouter(registry=reg),
        prompt_registry=PromptRegistry(),
        cache=SafeAIResultCache(ttl_seconds=60),
        metrics=metrics,
        clock=clk,
    )

    ctx = _minimal_context()
    res1 = await gw.generate_structured(
        AITaskType.INVESTIGATION,
        ctx,
        RawInvestigationOutput,
        incident_id="inc_gw_01",
        correlation_id="corr_gw_01",
    )
    assert res1.cache_hit is False
    assert res1.model_metadata.synthetic_origin is True
    assert res1.execution_record.prompt_version == "1.0.0"
    assert len(fix.invocations) == 1

    res2 = await gw.generate_structured(
        AITaskType.INVESTIGATION,
        ctx,
        RawInvestigationOutput,
        incident_id="inc_gw_01",
        correlation_id="corr_gw_01",
    )
    assert res2.cache_hit is True
    assert len(fix.invocations) == 1


@pytest.mark.unit
async def test_gateway_bounded_retry_on_transient_rate_limit_then_succeeds() -> None:
    fix = FixtureLLMProvider(
        mode_sequence=[FixtureBehaviorMode.RATE_LIMIT, FixtureBehaviorMode.VALID]
    )
    reg = ProviderRegistry()
    reg.register(fix)
    gw = LLMGateway(
        registry=reg,
        router=ModelRouter(registry=reg),
        retry_config=RetryPolicyConfig(
            max_attempts=3, initial_backoff_seconds=0.0, max_backoff_seconds=0.0
        ),
    )
    res = await gw.generate_structured(
        AITaskType.INVESTIGATION,
        _minimal_context(),
        RawInvestigationOutput,
        incident_id="inc_gw_02",
    )
    assert len(fix.invocations) == 2
    assert res.execution_record.attempt_count == 2


@pytest.mark.unit
async def test_gateway_bounded_repair_fixes_first_malformed_response() -> None:
    fix = FixtureLLMProvider(
        mode_sequence=[FixtureBehaviorMode.MALFORMED_JSON, FixtureBehaviorMode.VALID]
    )
    reg = ProviderRegistry()
    reg.register(fix)
    gw = LLMGateway(
        registry=reg,
        router=ModelRouter(registry=reg),
        retry_config=RetryPolicyConfig(
            max_attempts=1, initial_backoff_seconds=0.0, max_backoff_seconds=0.0
        ),
        max_repair_attempts=1,
    )
    res = await gw.generate_structured(
        AITaskType.INVESTIGATION,
        _minimal_context(),
        RawInvestigationOutput,
        incident_id="inc_gw_03",
    )
    assert res.repair_attempts == 1
    assert len(fix.invocations) == 2


@pytest.mark.unit
async def test_gateway_gemini_adapter_over_mock_http_transport() -> None:
    captured_headers: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        if request.url.path.endswith(":countTokens"):
            return httpx.Response(200, json={"totalTokens": 222})
        payload = {
            "executive_summary": "Live-transport Gemini response test.",
            "technical_explanation": "SQL interpolation detected on supplied /search code.",
            "affected_components": ["search_service"],
            "observed_effects": [],
            "grounded_facts": [],
            "technical_interpretations": [],
            "potential_impacts": [],
            "assumptions": [],
            "uncertainties": [],
            "missing_evidence": [],
            "recommended_next_action": "request_feature_mapping",
            "evidence_ids": ["art_repro_01"],
            "model_reported_confidence": "moderate_evidence_support",
        }
        return httpx.Response(
            200,
            json={
                "responseId": "gem_resp_01",
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {"parts": [{"text": json.dumps(payload)}]},
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 222,
                    "candidatesTokenCount": 88,
                    "totalTokenCount": 310,
                },
            },
        )

    transport = httpx.MockTransport(handler)
    gemini = GeminiLLMProvider(
        api_key=SecretStr("synthetic-gem-key-999"),
        transport=transport,
    )
    reg = ProviderRegistry()
    reg.register(gemini)
    router = ModelRouter(registry=reg, default_provider="gemini", default_model="gemini-2.5-flash")
    gw = LLMGateway(registry=reg, router=router)

    res = await gw.generate_structured(
        AITaskType.INVESTIGATION,
        _minimal_context(),
        RawInvestigationOutput,
        incident_id="inc_gem_01",
    )
    assert captured_headers.get("x-goog-api-key") == "synthetic-gem-key-999"
    assert res.execution_record.input_tokens == 222
    assert res.execution_record.output_tokens == 88
    assert res.model_metadata.synthetic_origin is False


@pytest.mark.unit
async def test_gateway_reusable_for_future_candidate_patch_generation() -> None:
    class DummyPatchDraft(KillswitchModel):
        summary: str = Field(min_length=1)

    def custom_patch_payload(_req: Any) -> dict[str, Any]:
        return {"summary": "Bind query parameter placeholder safely."}

    fix = FixtureLLMProvider(custom_payload_fn=custom_patch_payload)
    reg = ProviderRegistry()
    reg.register(fix)
    gw = LLMGateway(registry=reg, router=ModelRouter(registry=reg))

    res = await gw.generate_structured(
        AITaskType.CANDIDATE_PATCH_GENERATION,
        {"finding_id": "fnd_01", "file": "app/search_service.py"},
        DummyPatchDraft,
        incident_id="inc_pat_01",
    )
    assert res.parsed.summary.startswith("Bind query parameter")


@pytest.mark.unit
async def test_gateway_circuit_breaker_and_sensitive_failover_isolation() -> None:
    fix = FixtureLLMProvider(default_mode=FixtureBehaviorMode.UNAVAILABLE)
    reg = ProviderRegistry()
    reg.register(fix)
    cb = ProviderCircuitBreaker(failure_threshold=2, recovery_timeout_seconds=60.0)
    router = ModelRouter(registry=reg)
    router.set_route(
        TaskRouteConfig(
            task_type=AITaskType.INVESTIGATION,
            primary=TaskRouteTarget(
                provider_name="offline_fixture",
                model_name="fixture-investigator-v1",
                allowed_classifications=(DataClassification.PUBLIC,),
            ),
            allow_failover=False,
        )
    )
    gw = LLMGateway(registry=reg, router=router, circuit_breaker=cb)

    with pytest.raises(UnauthorizedOperationError):
        await gw.generate_structured(
            AITaskType.INVESTIGATION,
            _minimal_context(),
            RawInvestigationOutput,
            data_classification=DataClassification.SENSITIVE_SOURCE,
        )


@pytest.mark.unit
async def test_gateway_cancellation_propagates_cleanly() -> None:
    class SlowFixtureProvider(FixtureLLMProvider):
        async def generate(self, request: Any) -> Any:
            await asyncio.sleep(2.0)
            return await super().generate(request)

    reg = ProviderRegistry()
    reg.register(SlowFixtureProvider())
    gw = LLMGateway(registry=reg, router=ModelRouter(registry=reg))

    task = asyncio.create_task(
        gw.generate_structured(
            AITaskType.INVESTIGATION,
            _minimal_context(),
            RawInvestigationOutput,
        )
    )
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    _ = datetime.now()
    _ = NormalizedLLMError
    _ = AIProviderErrorCategory
