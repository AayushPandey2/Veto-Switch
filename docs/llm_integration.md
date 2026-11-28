# Killswitch X — LLM Integration Guide

## 1. Supported & Configured Providers
- **`offline_fixture` (`FixtureLLMProvider`)**: Default zero-credential deterministic provider for local development, CI tests, offline demos, and offline evaluations. Outputs always carry `synthetic_origin=True` and `provider="offline_fixture"`.
- **`gemini` (`GeminiLLMProvider`)**: Configurable REST adapter over `httpx.AsyncClient` targeting Gemini `:generateContent` and `:countTokens`. Model identifiers are NEVER hardcoded; operators must configure `KILLSWITCH_LLM_MODEL` explicitly.

## 2. Environment Variables (`AIServiceSettings`, prefix `KILLSWITCH_`)
| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `KILLSWITCH_LLM_PROVIDER` | `offline_fixture` | Provider identifier (`offline_fixture` or `gemini`). |
| `KILLSWITCH_LLM_MODEL` | `unconfigured` | Explicit model identifier required for live providers. |
| `KILLSWITCH_LLM_API_KEY` | `None` | `SecretStr` credential passed only via HTTP transport header (`x-goog-api-key`), never logged or placed in `GatewayLLMRequest`. |
| `KILLSWITCH_LLM_API_BASE_URL` | `None` | Optional override base URL for compatible Gemini endpoints. |
| `KILLSWITCH_LLM_TIMEOUT_SECONDS` | `30.0` | Per-attempt timeout ceiling (`(0, 300]`). |
| `KILLSWITCH_LLM_MAX_RETRIES` | `2` | Bounded retry count for retryable transport failures (`0..10`). |
| `KILLSWITCH_LLM_MAX_INPUT_TOKENS` | `6000` | Maximum input token ceiling before truncation / budget failure. |
| `KILLSWITCH_LLM_MAX_OUTPUT_TOKENS` | `1500` | Maximum generated response tokens. |
| `KILLSWITCH_LLM_FALLBACK_ENABLED` | `true` | Enables transparent `DETERMINISTIC_FALLBACK` when LLM fails or is unconfigured. |
| `KILLSWITCH_LLM_ALLOW_FAILOVER` | `false` | Disables silent failover across providers unless explicitly configured and permitted by `DataClassification`. |

Privileged platform keys (`KILLSWITCH_PLATFORM_*`) live strictly in `PlatformPrivilegedSettings` and remain inaccessible to `agent_core`.

## 3. Retry, Timeout & Repair Policies
- **Reused Infrastructure**: Transport retries reuse `agent_core/retry_policy.py` (`execute_with_retry`), obeying `overall_deadline_seconds`.
- **Retryable vs Non-Retryable**: Only `TIMEOUT`, `RATE_LIMIT`, and `TEMPORARY_UNAVAILABLE` retry automatically. `AUTHENTICATION_ERROR`, `INVALID_MODEL_CONFIGURATION`, `INVALID_REQUEST`, `CONTENT_RESTRICTION`, and `UNSUPPORTED_CAPABILITY` fail fast without pointless retries.
- **Bounded Output Repair**: Schema or semantic validation errors allow at most `max_repair_attempts` (default `1`) and NEVER attempt to bypass `CONTENT_RESTRICTION` safety blocks.

## 4. Structured Output & Capabilities
- `ProviderCapabilities` declares per-adapter support for `supports_native_schema`, `supports_structured_json`, `supports_tool_calling`, `supports_token_counting`, and `supports_temperature`.
- When native schema generation is supported (`GeminiLLMProvider` via `responseMimeType: "application/json"` + sanitized `responseSchema`), the gateway requests schema-constrained JSON; otherwise it parses strict JSON objects safely via `json.loads` without `eval`/`exec`.
- Missing provider usage metrics remain `None` rather than reporting fabricated zeros.
