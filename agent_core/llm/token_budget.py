"""Reusable token estimation, measurement, reservation, and per-task budget tracking."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field, StrictInt
from shared.enums import AIProviderErrorCategory
from shared.schemas import KillswitchModel

from agent_core.llm.error_mapping import NormalizedLLMError
from agent_core.llm.provider import GatewayLLMProvider


class TokenCountResult(KillswitchModel):
    """Token count paired with explicit provenance (``measured`` vs ``estimated``)."""

    tokens: StrictInt = Field(ge=0)
    source: Literal["measured", "estimated"]
    char_count: StrictInt = Field(ge=0)


class TokenBudgetPolicy(KillswitchModel):
    """Per-request token limits and headroom reservations."""

    max_input_tokens: StrictInt = Field(default=6000, ge=256, le=200_000)
    max_output_tokens: StrictInt = Field(default=1500, ge=64, le=32_000)
    reserved_system_tokens: StrictInt = Field(default=1100, ge=64, le=8000)
    reserved_schema_tokens: StrictInt = Field(default=350, ge=32, le=8000)
    reserved_tool_tokens: StrictInt = Field(default=300, ge=0, le=8000)
    max_total_task_tokens: StrictInt = Field(default=15_000, ge=512, le=500_000)

    def available_context_tokens(self, *, has_tools: bool = False) -> int:
        """Compute maximum token budget remaining for serialized incident context."""
        overhead = self.reserved_system_tokens + self.reserved_schema_tokens
        if has_tools:
            overhead += self.reserved_tool_tokens
        remaining = self.max_input_tokens - overhead
        return max(128, remaining)


def estimate_tokens(text_or_payload: str | dict[str, Any] | list[Any]) -> TokenCountResult:
    """Deterministically estimate token count without calling external APIs."""
    if isinstance(text_or_payload, str):
        serialized = text_or_payload
    else:
        serialized = json.dumps(text_or_payload, separators=(",", ":"), sort_keys=True)
    char_len = len(serialized)
    if char_len == 0:
        return TokenCountResult(tokens=0, source="estimated", char_count=0)
    # Conservative ~3.6 chars/token + small framing overhead for JSON/punctuation.
    estimated = max(1, (char_len + 3) // 4 + serialized.count("\n") // 4)
    return TokenCountResult(tokens=estimated, source="estimated", char_count=char_len)


class TokenBudgetManager:
    """Measures/estimates tokens and enforces input, output, and cumulative task limits."""

    def __init__(self, policy: TokenBudgetPolicy | None = None) -> None:
        self.policy = policy or TokenBudgetPolicy()

    async def count_text(
        self,
        text: str,
        *,
        provider: GatewayLLMProvider | None = None,
        model_name: str = "unconfigured",
    ) -> TokenCountResult:
        """Use provider token counting when supported, falling back to deterministic estimate."""
        if (
            provider is not None
            and provider.get_capabilities().supports_token_counting
            and model_name
        ):
            measured = await provider.count_tokens(text, model_name=model_name)
            if measured is not None and measured >= 0:
                return TokenCountResult(
                    tokens=measured, source="measured", char_count=len(text)
                )
        return estimate_tokens(text)

    def assert_input_within_budget(
        self,
        *,
        system_tokens: int,
        context_tokens: int,
        schema_tokens: int = 0,
        provider_name: str = "gateway",
    ) -> int:
        """Verify combined input fits within ``policy.max_input_tokens``."""
        total = system_tokens + context_tokens + schema_tokens
        if total > self.policy.max_input_tokens:
            raise NormalizedLLMError(
                f"Input payload ({total} tokens) exceeds configured limit "
                f"({self.policy.max_input_tokens} tokens).",
                category=AIProviderErrorCategory.TOKEN_BUDGET_EXCEEDED,
                provider=provider_name,
                context={
                    "total_tokens": total,
                    "max_input_tokens": self.policy.max_input_tokens,
                    "system_tokens": system_tokens,
                    "context_tokens": context_tokens,
                    "schema_tokens": schema_tokens,
                },
            )
        return total

    def clamp_output_tokens(self, requested: int | None, *, provider_max: int | None) -> int:
        """Clamp output token budget to policy and verified provider ceilings."""
        limit = self.policy.max_output_tokens
        if requested is not None:
            limit = min(limit, requested)
        if provider_max is not None:
            limit = min(limit, provider_max)
        return max(32, limit)
