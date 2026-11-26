"""Category A tests: provider interface, registry, capabilities, error normalization."""

from __future__ import annotations

import httpx
import pytest
from agent_core.llm.error_mapping import NormalizedLLMError, normalize_provider_error
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.providers.fixture import FixtureBehaviorMode, FixtureLLMProvider
from agent_core.llm.providers.gemini import GeminiLLMProvider
from agent_core.llm.request import GatewayLLMRequest
from agent_core.llm.routing import ModelRouter
from pydantic import SecretStr
from shared.enums import AIProviderErrorCategory, AITaskType
from shared.exceptions import ConfigurationError


@pytest.mark.unit
def test_provider_registry_registration_and_unknown_rejection() -> None:
    registry = ProviderRegistry()
    fixture = FixtureLLMProvider()
    registry.register(fixture)

    assert registry.has("offline_fixture")
    assert registry.get("offline_fixture") is fixture
    assert registry.list_providers() == ["offline_fixture"]

    with pytest.raises(ConfigurationError):
        registry.register(fixture)

    with pytest.raises(ConfigurationError):
        registry.get("nonexistent_provider")


@pytest.mark.unit
def test_fixture_provider_capabilities_and_synthetic_flag() -> None:
    fixture = FixtureLLMProvider()
    caps = fixture.get_capabilities()
    assert caps.is_synthetic_fixture is True
    assert caps.supports_structured_json is True
    assert caps.supports_native_schema is True


@pytest.mark.unit
async def test_gemini_missing_credentials_and_unconfigured_model() -> None:
    gemini_no_key = GeminiLLMProvider(api_key=None)
    req = GatewayLLMRequest(
        task_type=AITaskType.INVESTIGATION,
        provider_name="gemini",
        model_name="gemini-2.5-flash",
        system_instructions="System instructions.",
        user_message="User context.",
    )
    with pytest.raises(NormalizedLLMError) as exc_info:
        await gemini_no_key.generate(req)
    assert exc_info.value.category == AIProviderErrorCategory.AUTHENTICATION_ERROR
    assert exc_info.value.retryable is False

    gemini_with_key = GeminiLLMProvider(api_key=SecretStr("synthetic-test-key-000"))
    bad_model_req = req.model_copy(update={"model_name": "unconfigured"})
    with pytest.raises(NormalizedLLMError) as exc_model:
        await gemini_with_key.generate(bad_model_req)
    assert exc_model.value.category == AIProviderErrorCategory.INVALID_MODEL_CONFIGURATION
    assert exc_model.value.retryable is False


@pytest.mark.unit
def test_provider_error_normalization_strips_secrets() -> None:
    raw = RuntimeError("HTTP 401 unauthorized for api_key=sk-secret-value-12345")
    norm = normalize_provider_error(raw, provider="gemini", status_code=401)
    assert norm.category == AIProviderErrorCategory.AUTHENTICATION_ERROR
    assert norm.retryable is False
    assert "sk-secret-value-12345" not in norm.message

    rate_norm = normalize_provider_error(
        RuntimeError("429 quota exceeded"),
        provider="gemini",
        status_code=429,
        retry_after_seconds=2.5,
    )
    assert rate_norm.category == AIProviderErrorCategory.RATE_LIMIT
    assert rate_norm.retryable is True
    assert rate_norm.retry_after_seconds == 2.5

    timeout_norm = normalize_provider_error(httpx.ReadTimeout("timed out"), provider="gemini")
    assert timeout_norm.category == AIProviderErrorCategory.TIMEOUT
    assert timeout_norm.retryable is True


@pytest.mark.unit
def test_model_router_rejects_unconfigured_live_model() -> None:
    reg = ProviderRegistry()
    reg.register(GeminiLLMProvider(api_key=SecretStr("synth-key")))
    router = ModelRouter(
        registry=reg, default_provider="gemini", default_model="unconfigured"
    )
    with pytest.raises(ConfigurationError):
        router.resolve_candidate_targets(
            task_type=AITaskType.INVESTIGATION,
            data_classification="restricted_security",  # type: ignore[arg-type]
        )


@pytest.mark.unit
async def test_fixture_timeout_mode_raises_normalized_timeout() -> None:
    fix = FixtureLLMProvider(default_mode=FixtureBehaviorMode.TIMEOUT)
    req = GatewayLLMRequest(
        task_type=AITaskType.INVESTIGATION,
        provider_name="offline_fixture",
        model_name="fixture-investigator-v1",
        system_instructions="Sys",
        user_message="User",
    )
    with pytest.raises(NormalizedLLMError) as exc:
        await fix.generate(req)
    assert exc.value.category == AIProviderErrorCategory.TIMEOUT
