"""Provider-independent LLM interface and capability descriptor."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import Field, StrictBool, StrictInt
from shared.schemas import KillswitchModel

from agent_core.llm.request import GatewayLLMRequest
from agent_core.llm.response import GatewayLLMResponse


class ProviderCapabilities(KillswitchModel):
    """Explicit capability matrix declared by an LLM provider adapter."""

    supports_structured_json: StrictBool = True
    supports_native_schema: StrictBool = False
    supports_tool_calling: StrictBool = False
    supports_token_counting: StrictBool = False
    supports_temperature: StrictBool = True
    max_context_tokens: StrictInt | None = Field(default=None, gt=0)
    max_output_tokens: StrictInt | None = Field(default=None, gt=0)
    supported_parameters: tuple[str, ...] = ("temperature", "max_output_tokens")
    is_synthetic_fixture: StrictBool = False


@runtime_checkable
class GatewayLLMProvider(Protocol):
    """Provider-independent asynchronous LLM adapter contract."""

    provider_name: str

    async def generate(self, request: GatewayLLMRequest) -> GatewayLLMResponse:
        """Execute a bounded model generation call and return normalized response."""
        ...

    def get_capabilities(self) -> ProviderCapabilities:
        """Return the adapter's verified parameter & capability support matrix."""
        ...

    async def count_tokens(self, text: str, *, model_name: str) -> int | None:
        """Return measured input token count if supported, otherwise ``None``."""
        ...
