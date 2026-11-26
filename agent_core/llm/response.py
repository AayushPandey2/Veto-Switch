"""Provider-independent structured LLM response and tool-call request models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt
from shared.identifiers import utc_now
from shared.schemas import KillswitchModel, UtcDatetime


class ToolCallRequest(KillswitchModel):
    """Unvalidated tool call requested by an LLM (must pass policy outside the model)."""

    call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class GatewayLLMResponse(KillswitchModel):
    """Normalized provider response preserving unknown token usage as ``None``."""

    request_id: str = Field(min_length=4, max_length=128)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    provider_response_id: str | None = None
    content: str = ""
    structured_response: dict[str, Any] | None = None
    requested_tool_calls: list[ToolCallRequest] = Field(default_factory=list)
    finish_reason: str | None = None
    input_tokens: StrictInt | None = Field(default=None, ge=0)
    output_tokens: StrictInt | None = Field(default=None, ge=0)
    total_tokens: StrictInt | None = Field(default=None, ge=0)
    latency_ms: float | None = Field(default=None, ge=0.0)
    attempt_count: StrictInt = Field(default=1, ge=1)
    timestamp: UtcDatetime = Field(default_factory=utc_now)
    status: Literal["ok", "error", "blocked", "incomplete"] = "ok"
    sanitized_error: str | None = None
    synthetic_origin: StrictBool = False
