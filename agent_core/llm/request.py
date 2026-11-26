"""Provider-independent structured LLM request contract for the central LLMGateway."""

from __future__ import annotations

import re
import uuid
from typing import Any

from pydantic import Field, StrictInt, field_validator
from shared.enums import AITaskType, DataClassification
from shared.schemas import KillswitchModel

_FORBIDDEN_CREDENTIAL_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "llm_api_key",
        "management_token",
        "flagsmith_management_token",
        "flagsmith_environment_key",
        "approval_signing_secret",
        "database_url",
        "password",
        "passwd",
        "private_key",
        "secret_key",
        "session_token",
        "access_token",
        "refresh_token",
        "authorization_header",
    }
)

_CREDENTIAL_VALUE_PATTERN = re.compile(
    r"(?:Bearer\s+[A-Za-z0-9._\-]{12,}|AIza[0-9A-Za-z_\-]{20,}|sk-[A-Za-z0-9]{16,})"
)


def _new_request_id() -> str:
    return f"lreq_{uuid.uuid4().hex[:16]}"


def _assert_no_embedded_secrets(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            key_lower = str(k).lower()
            if key_lower in _FORBIDDEN_CREDENTIAL_KEYS:
                raise ValueError(
                    f"Credential key {k!r} at {path}.{k} is forbidden inside GatewayLLMRequest."
                )
            _assert_no_embedded_secrets(v, path=f"{path}.{k}")
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            _assert_no_embedded_secrets(item, path=f"{path}[{idx}]")
    elif isinstance(value, str) and _CREDENTIAL_VALUE_PATTERN.search(value):
        raise ValueError(
            f"Potential unredacted secret pattern detected in {path}; redact before sending to LLM."
        )


class GatewayLLMRequest(KillswitchModel):
    """Typed, secret-free model request passed from ``LLMGateway`` to a provider adapter."""

    request_id: str = Field(default_factory=_new_request_id, min_length=4, max_length=128)
    incident_id: str | None = Field(default=None, min_length=4, max_length=128)
    correlation_id: str | None = Field(default=None, min_length=4, max_length=128)
    task_type: AITaskType
    provider_name: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    system_instructions: str = Field(min_length=1)
    structured_context: dict[str, Any] = Field(default_factory=dict)
    user_message: str = Field(min_length=1)
    expected_response_schema: dict[str, Any] | None = None
    temperature: float | None = Field(default=0.0, ge=0.0, le=1.0)
    max_output_tokens: StrictInt = Field(default=1500, ge=32, le=32_000)
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    allowed_tools: list[dict[str, Any]] = Field(default_factory=list)
    prompt_version: str = Field(default="1.0.0", min_length=1)
    prompt_hash: str | None = None
    context_hash: str | None = None
    data_classification: DataClassification = DataClassification.RESTRICTED_SECURITY
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("structured_context")
    @classmethod
    def _check_context_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        _assert_no_embedded_secrets(value, path="structured_context")
        return value

    @field_validator("metadata")
    @classmethod
    def _check_metadata_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        _assert_no_embedded_secrets(value, path="metadata")
        return value

    @field_validator("system_instructions", "user_message")
    @classmethod
    def _check_text_secrets(cls, value: str) -> str:
        if _CREDENTIAL_VALUE_PATTERN.search(value):
            raise ValueError("Unredacted API/Bearer credential detected in prompt text.")
        return value
