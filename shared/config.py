"""Typed configuration management separating AI-readable settings from platform secrets.

Security boundary:
    - ``AIServiceSettings`` (prefix ``KILLSWITCH_``) exposes ONLY non-privileged
      settings and read-only service endpoints needed by ``agent_core`` and
      ``remediation``.
    - ``PlatformPrivilegedSettings`` (prefix ``KILLSWITCH_PLATFORM_``) holds
      database URLs, Flagsmith management tokens, and approval signing secrets.
      AI modules must NEVER import or access ``PlatformPrivilegedSettings``.
    - Shared modules and unit tests import cleanly with zero live credentials.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from shared.constants import (
    DEFAULT_ARTIFACT_DIR,
    DEFAULT_DEPENDENCY_GRAPH_PATH,
    DEFAULT_LLM_MAX_CONTEXT_CHARS,
    DEFAULT_LLM_MAX_RETRIES,
    DEFAULT_LLM_TIMEOUT_SECONDS,
    DEFAULT_PROPOSAL_EXPIRATION_SECONDS,
    DEFAULT_ROLLOUT_POLICY_PATH,
    DEFAULT_ROUTE_REGISTRY_PATH,
)
from shared.exceptions import ConfigurationError
from shared.schemas import DependencyGraph, RolloutPolicyConfig, RouteFlagRegistry


class AIServiceSettings(BaseSettings):
    """Non-privileged configuration safe for AI orchestration and remediation modules."""

    model_config = SettingsConfigDict(
        env_prefix="KILLSWITCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: str = Field(default="development", min_length=1)
    log_level: str = Field(default="INFO", min_length=1)
    log_format: str = Field(default="json", min_length=1)

    llm_provider: str = Field(default="offline_fixture", min_length=1)
    llm_model: str = Field(default="unconfigured", min_length=1)
    llm_api_key: SecretStr | None = Field(default=None)
    llm_timeout_seconds: float = Field(default=DEFAULT_LLM_TIMEOUT_SECONDS, gt=0.0, le=300.0)
    llm_max_retries: int = Field(default=DEFAULT_LLM_MAX_RETRIES, ge=0, le=10)
    llm_max_context_chars: int = Field(
        default=DEFAULT_LLM_MAX_CONTEXT_CHARS, ge=1000, le=500_000
    )
    llm_max_input_tokens: int = Field(default=6000, ge=256, le=200_000)
    llm_max_output_tokens: int = Field(default=1500, ge=64, le=32_000)
    llm_fallback_enabled: bool = Field(default=True)
    llm_api_base_url: str | None = Field(default=None)
    llm_allow_failover: bool = Field(default=False)

    flagsmith_read_url: str = Field(default="http://127.0.0.1:8001/readonly/flags")
    security_verifier_url: str = Field(default="http://127.0.0.1:8002/verify")
    patch_test_runner_url: str = Field(default="http://127.0.0.1:8003/patch-tests")

    artifact_dir: Path = Field(default=Path(DEFAULT_ARTIFACT_DIR))
    route_registry_path: Path = Field(default=Path(DEFAULT_ROUTE_REGISTRY_PATH))
    dependency_graph_path: Path = Field(default=Path(DEFAULT_DEPENDENCY_GRAPH_PATH))
    rollout_policy_path: Path = Field(default=Path(DEFAULT_ROLLOUT_POLICY_PATH))
    default_proposal_expiration_seconds: int = Field(
        default=DEFAULT_PROPOSAL_EXPIRATION_SECONDS, ge=30, le=86400
    )

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"Unsupported log_level {value!r}; expected one of {sorted(allowed)}.")
        return upper

    @field_validator("log_format")
    @classmethod
    def _validate_log_format(cls, value: str) -> str:
        lowered = value.lower()
        if lowered not in {"json", "console"}:
            raise ValueError("log_format must be 'json' or 'console'.")
        return lowered

    def safe_summary(self) -> dict[str, Any]:
        """Return a credential-safe dictionary suitable for diagnostics."""
        return {
            "app_env": self.app_env,
            "log_level": self.log_level,
            "log_format": self.log_format,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "llm_api_key_configured": self.llm_api_key is not None,
            "llm_timeout_seconds": self.llm_timeout_seconds,
            "llm_max_retries": self.llm_max_retries,
            "llm_max_context_chars": self.llm_max_context_chars,
            "llm_max_input_tokens": self.llm_max_input_tokens,
            "llm_max_output_tokens": self.llm_max_output_tokens,
            "llm_fallback_enabled": self.llm_fallback_enabled,
            "llm_api_base_url": self.llm_api_base_url,
            "llm_allow_failover": self.llm_allow_failover,
            "flagsmith_read_url": self.flagsmith_read_url,
            "security_verifier_url": self.security_verifier_url,
            "patch_test_runner_url": self.patch_test_runner_url,
            "artifact_dir": str(self.artifact_dir),
            "route_registry_path": str(self.route_registry_path),
            "dependency_graph_path": str(self.dependency_graph_path),
            "rollout_policy_path": str(self.rollout_policy_path),
            "default_proposal_expiration_seconds": self.default_proposal_expiration_seconds,
        }


class PlatformPrivilegedSettings(BaseSettings):
    """Privileged platform-only configuration (never exposed to AI modules)."""

    model_config = SettingsConfigDict(
        env_prefix="KILLSWITCH_PLATFORM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str = Field(default="sqlite:///./killswitch_local.db")
    flagsmith_environment_key: SecretStr | None = Field(default=None)
    flagsmith_management_token: SecretStr | None = Field(default=None)
    approval_signing_secret: SecretStr | None = Field(default=None)

    def safe_summary(self) -> dict[str, Any]:
        """Return redacted diagnostic status without leaking secrets or DB credentials."""
        return {
            "database_configured": bool(self.database_url),
            "flagsmith_environment_key_configured": self.flagsmith_environment_key is not None,
            "flagsmith_management_token_configured": self.flagsmith_management_token is not None,
            "approval_signing_secret_configured": self.approval_signing_secret is not None,
        }


def load_ai_settings(**overrides: Any) -> AIServiceSettings:
    """Load and validate non-privileged AI/shared settings."""
    try:
        return AIServiceSettings(**overrides)
    except Exception as exc:
        raise ConfigurationError(
            "Failed to load AIServiceSettings.",
            context={"reason": str(exc)},
        ) from exc


def _load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigurationError(
            f"Configuration file does not exist: {path}",
            context={"path": str(path)},
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigurationError(
            f"Failed to parse JSON configuration file: {path}",
            context={"path": str(path), "reason": str(exc)},
        ) from exc
    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Configuration root must be a JSON object: {path}",
            context={"path": str(path)},
        )
    return data


def load_route_registry(path: Path | str = DEFAULT_ROUTE_REGISTRY_PATH) -> RouteFlagRegistry:
    """Load and validate ``config/route_flag_map.json``."""
    raw = _load_json_file(Path(path))
    try:
        return RouteFlagRegistry.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(
            "RouteFlagRegistry configuration failed schema validation.",
            context={"path": str(path), "reason": str(exc)},
        ) from exc


def load_dependency_graph(path: Path | str = DEFAULT_DEPENDENCY_GRAPH_PATH) -> DependencyGraph:
    """Load and validate ``config/dependency_graph.json``."""
    raw = _load_json_file(Path(path))
    try:
        return DependencyGraph.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(
            "DependencyGraph configuration failed schema validation.",
            context={"path": str(path), "reason": str(exc)},
        ) from exc


def load_rollout_policy(path: Path | str = DEFAULT_ROLLOUT_POLICY_PATH) -> RolloutPolicyConfig:
    """Load and validate ``config/rollout_policy.json``."""
    raw = _load_json_file(Path(path))
    try:
        return RolloutPolicyConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(
            "RolloutPolicyConfig failed schema validation.",
            context={"path": str(path), "reason": str(exc)},
        ) from exc
