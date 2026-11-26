"""Configurable live Gemini REST provider adapter built on ``httpx.AsyncClient``.

Uses the official Gemini REST API endpoints (`:generateContent` and `:countTokens`)
with configurable model name, endpoint URL, and API key passed exclusively in the
HTTP request header (never embedded inside ``GatewayLLMRequest`` or logs).
Supports injecting an ``httpx.AsyncBaseTransport`` for offline transport testing.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
from pydantic import SecretStr
from shared.enums import AIProviderErrorCategory
from shared.identifiers import utc_now
from shared.logging_config import redact_text

from agent_core.llm.error_mapping import (
    NormalizedLLMError,
    normalize_provider_error,
    parse_retry_after_header,
)
from agent_core.llm.provider import GatewayLLMProvider, ProviderCapabilities
from agent_core.llm.request import GatewayLLMRequest
from agent_core.llm.response import GatewayLLMResponse, ToolCallRequest

_DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"
_UNSUPPORTED_GEMINI_SCHEMA_KEYS: frozenset[str] = frozenset(
    {"$schema", "$defs", "definitions", "additionalProperties", "title", "default", "$ref"}
)


def _to_gemini_response_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve simple local ``$defs`` references and strip unsupported OpenAPI keywords."""
    defs = schema.get("$defs", {}) if isinstance(schema.get("$defs"), dict) else {}

    def _transform(node: Any) -> Any:
        if isinstance(node, list):
            return [_transform(item) for item in node]
        if not isinstance(node, dict):
            return node
        if "$ref" in node and isinstance(node["$ref"], str):
            ref_name = node["$ref"].rsplit("/", 1)[-1]
            if ref_name in defs and isinstance(defs[ref_name], dict):
                return _transform(defs[ref_name])
        cleaned: dict[str, Any] = {}
        for k, v in node.items():
            if k in _UNSUPPORTED_GEMINI_SCHEMA_KEYS:
                continue
            if k == "anyOf" and isinstance(v, list):
                non_null = [
                    item
                    for item in v
                    if not (isinstance(item, dict) and item.get("type") == "null")
                ]
                if len(non_null) == 1 and isinstance(non_null[0], dict):
                    resolved = _transform(non_null[0])
                    if isinstance(resolved, dict):
                        cleaned.update(resolved)
                        cleaned["nullable"] = True
                    continue
            cleaned[k] = _transform(v)
        return cleaned

    result = _transform(schema)
    return result if isinstance(result, dict) else {}


class GeminiLLMProvider(GatewayLLMProvider):
    """Gemini REST API adapter (zero hardcoded credentials or invented model names)."""

    provider_name: str = "gemini"

    def __init__(
        self,
        *,
        api_key: SecretStr | None,
        base_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        default_timeout_seconds: float = 30.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = (base_url or _DEFAULT_GEMINI_BASE_URL).rstrip("/")
        self._transport = transport
        self._default_timeout_seconds = default_timeout_seconds
        self._capabilities = ProviderCapabilities(
            supports_structured_json=True,
            supports_native_schema=True,
            supports_tool_calling=True,
            supports_token_counting=True,
            supports_temperature=True,
            max_context_tokens=None,
            max_output_tokens=None,
            supported_parameters=(
                "temperature",
                "maxOutputTokens",
                "responseMimeType",
                "responseSchema",
                "tools",
            ),
            is_synthetic_fixture=False,
        )

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def _require_api_key_and_model(self, model_name: str) -> tuple[str, str]:
        if self._api_key is None or not self._api_key.get_secret_value().strip():
            raise NormalizedLLMError(
                "Gemini API key is not configured.",
                category=AIProviderErrorCategory.AUTHENTICATION_ERROR,
                provider=self.provider_name,
            )
        normalized_model = model_name.strip()
        if not normalized_model or normalized_model.lower() == "unconfigured":
            raise NormalizedLLMError(
                "Gemini model name is unconfigured; set KILLSWITCH_LLM_MODEL explicitly.",
                category=AIProviderErrorCategory.INVALID_MODEL_CONFIGURATION,
                provider=self.provider_name,
            )
        return normalized_model, self._api_key.get_secret_value()

    async def count_tokens(self, text: str, *, model_name: str) -> int | None:
        normalized_model, api_key_val = self._require_api_key_and_model(model_name)
        url = f"{self._base_url}/v1beta/models/{normalized_model}:countTokens"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key_val,
        }
        body = {"contents": [{"role": "user", "parts": [{"text": text}]}]}
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._default_timeout_seconds
            ) as client:
                resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                return None
            data = resp.json()
            total = data.get("totalTokens")
            return int(total) if isinstance(total, int) and not isinstance(total, bool) else None
        except Exception:
            return None

    async def generate(self, request: GatewayLLMRequest) -> GatewayLLMResponse:
        normalized_model, api_key_val = self._require_api_key_and_model(request.model_name)
        url = f"{self._base_url}/v1beta/models/{normalized_model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key_val,
        }

        generation_config: dict[str, Any] = {
            "maxOutputTokens": request.max_output_tokens,
        }
        if request.temperature is not None:
            generation_config["temperature"] = request.temperature
        if request.expected_response_schema is not None:
            generation_config["responseMimeType"] = "application/json"
            generation_config["responseSchema"] = _to_gemini_response_schema(
                request.expected_response_schema
            )

        body: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": request.system_instructions}]},
            "contents": [{"role": "user", "parts": [{"text": request.user_message}]}],
            "generationConfig": generation_config,
        }
        if request.allowed_tools:
            body["tools"] = [{"functionDeclarations": request.allowed_tools}]

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=request.timeout_seconds
            ) as client:
                resp = await client.post(url, headers=headers, json=body)
        except Exception as exc:
            raise normalize_provider_error(exc, provider=self.provider_name) from exc

        elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
        if resp.status_code >= 400:
            retry_after = parse_retry_after_header(resp.headers.get("Retry-After"))
            raise normalize_provider_error(
                RuntimeError(redact_text(resp.text[:300])),
                provider=self.provider_name,
                status_code=resp.status_code,
                retry_after_seconds=retry_after,
            )

        raw_data = resp.json()
        prompt_feedback = raw_data.get("promptFeedback", {})
        if isinstance(prompt_feedback, dict) and prompt_feedback.get("blockReason"):
            raise NormalizedLLMError(
                f"Gemini blocked request content ({prompt_feedback['blockReason']}).",
                category=AIProviderErrorCategory.CONTENT_RESTRICTION,
                provider=self.provider_name,
                status_code=resp.status_code,
            )

        candidates = raw_data.get("candidates", [])
        first = candidates[0] if isinstance(candidates, list) and candidates else {}
        finish_reason = first.get("finishReason") if isinstance(first, dict) else None
        if finish_reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT"}:
            raise NormalizedLLMError(
                f"Gemini output restricted by safety policy ({finish_reason}).",
                category=AIProviderErrorCategory.CONTENT_RESTRICTION,
                provider=self.provider_name,
                status_code=resp.status_code,
            )

        parts = (
            first.get("content", {}).get("parts", [])
            if isinstance(first, dict) and isinstance(first.get("content"), dict)
            else []
        )
        text_chunks: list[str] = []
        tool_calls: list[ToolCallRequest] = []
        for idx, part in enumerate(parts):
            if not isinstance(part, dict):
                continue
            if isinstance(part.get("text"), str):
                text_chunks.append(part["text"])
            if isinstance(part.get("functionCall"), dict):
                fc = part["functionCall"]
                tool_calls.append(
                    ToolCallRequest(
                        call_id=f"gem_call_{idx + 1}",
                        tool_name=str(fc.get("name", "")),
                        arguments=(
                            fc.get("args") if isinstance(fc.get("args"), dict) else {}
                        ),
                    )
                )

        content_str = "\n".join(text_chunks).strip()
        structured_payload: dict[str, Any] | None = None
        if content_str:
            try:
                parsed = json.loads(content_str)
                if isinstance(parsed, dict):
                    structured_payload = parsed
            except json.JSONDecodeError:
                structured_payload = None

        usage = raw_data.get("usageMetadata", {})
        in_tok = (
            usage.get("promptTokenCount")
            if isinstance(usage, dict) and isinstance(usage.get("promptTokenCount"), int)
            else None
        )
        out_tok = (
            usage.get("candidatesTokenCount")
            if isinstance(usage, dict) and isinstance(usage.get("candidatesTokenCount"), int)
            else None
        )
        tot_tok = (
            usage.get("totalTokenCount")
            if isinstance(usage, dict) and isinstance(usage.get("totalTokenCount"), int)
            else None
        )

        return GatewayLLMResponse(
            request_id=request.request_id,
            provider=self.provider_name,
            model=normalized_model,
            provider_response_id=raw_data.get("responseId"),
            content=content_str,
            structured_response=structured_payload,
            requested_tool_calls=tool_calls,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=tot_tok,
            latency_ms=elapsed_ms,
            timestamp=utc_now(),
            status="incomplete" if finish_reason == "MAX_TOKENS" else "ok",
            synthetic_origin=False,
        )
