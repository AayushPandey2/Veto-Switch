"""Top-level factory assembling configured ``LLMGateway`` from ``AIServiceSettings``."""

from __future__ import annotations

import httpx
from shared.config import AIServiceSettings, load_ai_settings

from agent_core.llm.cache import SafeAIResultCache
from agent_core.llm.gateway import LLMGateway, ProviderCircuitBreaker
from agent_core.llm.observability import AIMetricsCollector
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.providers.fixture import FixtureBehaviorMode, FixtureLLMProvider
from agent_core.llm.providers.gemini import GeminiLLMProvider
from agent_core.llm.routing import ModelRouter
from agent_core.llm.token_budget import TokenBudgetManager, TokenBudgetPolicy
from agent_core.prompts.registry import PromptRegistry
from agent_core.retry_policy import RetryPolicyConfig
from agent_core.tools.registry import ToolRegistry, build_default_investigation_tool_registry


def build_default_gateway(
    settings: AIServiceSettings | None = None,
    *,
    fixture_mode: FixtureBehaviorMode = FixtureBehaviorMode.VALID,
    fixture_provider: FixtureLLMProvider | None = None,
    gemini_transport: httpx.AsyncBaseTransport | None = None,
    tool_registry: ToolRegistry | None = None,
    metrics: AIMetricsCollector | None = None,
    enable_cache: bool = True,
    max_repair_attempts: int = 1,
) -> LLMGateway:
    """Assemble a configured, secret-safe ``LLMGateway`` without bypassing boundaries."""
    cfg = settings or load_ai_settings()
    registry = ProviderRegistry()

    registry.register(fixture_provider or FixtureLLMProvider(default_mode=fixture_mode))
    registry.register(
        GeminiLLMProvider(
            api_key=cfg.llm_api_key,
            base_url=cfg.llm_api_base_url,
            transport=gemini_transport,
            default_timeout_seconds=cfg.llm_timeout_seconds,
        )
    )

    router = ModelRouter.from_settings(cfg, registry=registry)
    budget_policy = TokenBudgetPolicy(
        max_input_tokens=cfg.llm_max_input_tokens,
        max_output_tokens=cfg.llm_max_output_tokens,
    )
    retry_cfg = RetryPolicyConfig(
        max_attempts=max(1, cfg.llm_max_retries + 1),
        initial_backoff_seconds=0.05,
        backoff_multiplier=2.0,
        max_backoff_seconds=0.5,
        operation_timeout_seconds=cfg.llm_timeout_seconds,
        overall_deadline_seconds=min(
            600.0, cfg.llm_timeout_seconds * max(1, cfg.llm_max_retries + 2)
        ),
    )
    return LLMGateway(
        registry=registry,
        router=router,
        prompt_registry=PromptRegistry(),
        token_budget_manager=TokenBudgetManager(budget_policy),
        tool_registry=tool_registry or build_default_investigation_tool_registry(),
        cache=SafeAIResultCache() if enable_cache else None,
        metrics=metrics or AIMetricsCollector(),
        retry_config=retry_cfg,
        max_repair_attempts=max_repair_attempts,
        circuit_breaker=ProviderCircuitBreaker(),
    )
