"""Explicit registry for configured LLM provider adapters."""

from __future__ import annotations

from shared.exceptions import ConfigurationError

from agent_core.llm.provider import GatewayLLMProvider, ProviderCapabilities


class ProviderRegistry:
    """Central registry mapping provider identifiers to validated provider adapters."""

    def __init__(self) -> None:
        self._providers: dict[str, GatewayLLMProvider] = {}

    def register(self, provider: GatewayLLMProvider, *, overwrite: bool = False) -> None:
        """Register a provider adapter; rejects duplicates unless ``overwrite=True``."""
        name = provider.provider_name.strip().lower()
        if not name:
            raise ConfigurationError("Provider name cannot be empty.")
        if name in self._providers and not overwrite:
            raise ConfigurationError(
                f"LLM provider {name!r} is already registered.",
                context={"provider": name},
            )
        self._providers[name] = provider

    def unregister(self, provider_name: str) -> None:
        """Remove a registered provider by name."""
        key = provider_name.strip().lower()
        self._providers.pop(key, None)

    def get(self, provider_name: str) -> GatewayLLMProvider:
        """Retrieve a registered provider or raise ``ConfigurationError``."""
        key = provider_name.strip().lower()
        provider = self._providers.get(key)
        if provider is None:
            raise ConfigurationError(
                f"Unknown LLM provider {provider_name!r}.",
                context={
                    "requested_provider": provider_name,
                    "registered_providers": sorted(self._providers.keys()),
                },
            )
        return provider

    def has(self, provider_name: str) -> bool:
        """Return True iff the named provider is registered."""
        return provider_name.strip().lower() in self._providers

    def list_providers(self) -> list[str]:
        """Return sorted names of all registered providers."""
        return sorted(self._providers.keys())

    def get_capabilities(self, provider_name: str) -> ProviderCapabilities:
        """Return declared capabilities for a registered provider."""
        return self.get(provider_name).get_capabilities()
