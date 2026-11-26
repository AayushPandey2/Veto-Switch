"""Normalized provider-independent LLM error categories and secret-safe sanitization."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from shared.enums import AIProviderErrorCategory
from shared.exceptions import KillswitchError, LLMProviderError, LLMResponseValidationError
from shared.logging_config import redact_text

RETRYABLE_ERROR_CATEGORIES: frozenset[AIProviderErrorCategory] = frozenset(
    {
        AIProviderErrorCategory.RATE_LIMIT,
        AIProviderErrorCategory.TIMEOUT,
        AIProviderErrorCategory.TEMPORARY_UNAVAILABLE,
    }
)


class NormalizedLLMError(LLMProviderError):
    """Normalized provider failure with stable application category and sanitized context."""

    default_error_code = "LLM_NORMALIZED_ERROR"

    def __init__(
        self,
        message: str,
        *,
        category: AIProviderErrorCategory,
        provider: str,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        retryable = category in RETRYABLE_ERROR_CATEGORIES
        merged_context: dict[str, Any] = {
            "category": category.value,
            "provider": provider,
            **(context or {}),
        }
        if status_code is not None:
            merged_context["status_code"] = status_code
        if retry_after_seconds is not None:
            merged_context["retry_after_seconds"] = retry_after_seconds
        super().__init__(
            redact_text(message),
            error_code=f"LLM_{category.value.upper()}",
            context=merged_context,
            retryable=retryable,
        )
        self.category = category
        self.provider = provider
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


def parse_retry_after_header(value: str | None) -> float | None:
    """Parse numeric ``Retry-After`` seconds cleanly; return None if absent or invalid."""
    if not value:
        return None
    stripped = value.strip()
    try:
        parsed = float(stripped)
        return max(0.0, parsed)
    except ValueError:
        return None


def normalize_provider_error(
    exc: Exception,
    *,
    provider: str,
    status_code: int | None = None,
    retry_after_seconds: float | None = None,
) -> NormalizedLLMError:
    """Map provider-specific exceptions and HTTP statuses into ``NormalizedLLMError``."""
    if isinstance(exc, NormalizedLLMError):
        return exc

    if isinstance(exc, LLMResponseValidationError):
        return NormalizedLLMError(
            redact_text(exc.message),
            category=AIProviderErrorCategory.RESPONSE_VALIDATION_FAILURE,
            provider=provider,
            context=exc.context,
        )

    if isinstance(exc, (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException)):
        return NormalizedLLMError(
            f"Provider '{provider}' request timed out.",
            category=AIProviderErrorCategory.TIMEOUT,
            provider=provider,
            status_code=status_code or 504,
            retry_after_seconds=retry_after_seconds,
        )

    if isinstance(exc, httpx.TransportError):
        return NormalizedLLMError(
            f"Provider '{provider}' transport error: {redact_text(str(exc))}",
            category=AIProviderErrorCategory.TEMPORARY_UNAVAILABLE,
            provider=provider,
            status_code=status_code,
            retry_after_seconds=retry_after_seconds,
        )

    msg = redact_text(str(exc))
    lowered = msg.lower()

    if status_code in {401, 403} or "api key" in lowered or "unauthorized" in lowered:
        return NormalizedLLMError(
            f"Authentication error for provider '{provider}'.",
            category=AIProviderErrorCategory.AUTHENTICATION_ERROR,
            provider=provider,
            status_code=status_code,
        )
    if status_code == 404 or "model not found" in lowered or "invalid model" in lowered:
        return NormalizedLLMError(
            f"Invalid or unknown model configuration for provider '{provider}'.",
            category=AIProviderErrorCategory.INVALID_MODEL_CONFIGURATION,
            provider=provider,
            status_code=status_code,
        )
    if status_code == 429 or "rate limit" in lowered or "quota" in lowered:
        return NormalizedLLMError(
            f"Rate limit exceeded for provider '{provider}'.",
            category=AIProviderErrorCategory.RATE_LIMIT,
            provider=provider,
            status_code=status_code or 429,
            retry_after_seconds=retry_after_seconds,
        )
    if status_code in {500, 502, 503, 504} or "unavailable" in lowered:
        return NormalizedLLMError(
            f"Provider '{provider}' temporarily unavailable.",
            category=AIProviderErrorCategory.TEMPORARY_UNAVAILABLE,
            provider=provider,
            status_code=status_code,
            retry_after_seconds=retry_after_seconds,
        )
    if status_code == 400:
        if "token" in lowered or "context length" in lowered or "too large" in lowered:
            return NormalizedLLMError(
                f"Provider '{provider}' rejected input for exceeding token limits.",
                category=AIProviderErrorCategory.TOKEN_BUDGET_EXCEEDED,
                provider=provider,
                status_code=400,
            )
        return NormalizedLLMError(
            f"Provider '{provider}' rejected request as invalid.",
            category=AIProviderErrorCategory.INVALID_REQUEST,
            provider=provider,
            status_code=400,
        )
    if isinstance(exc, KillswitchError):
        return NormalizedLLMError(
            redact_text(exc.message),
            category=(
                AIProviderErrorCategory.TEMPORARY_UNAVAILABLE
                if exc.retryable
                else AIProviderErrorCategory.UNKNOWN_PROVIDER_ERROR
            ),
            provider=provider,
            status_code=status_code,
            context=exc.context,
        )

    return NormalizedLLMError(
        f"Provider '{provider}' failed with an unclassified error ({type(exc).__name__}).",
        category=AIProviderErrorCategory.UNKNOWN_PROVIDER_ERROR,
        provider=provider,
        status_code=status_code,
    )
