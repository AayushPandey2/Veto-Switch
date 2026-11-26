"""Configurable per-task model routing with strict capability and sensitivity enforcement."""

from __future__ import annotations

from pydantic import Field, StrictBool, StrictInt
from shared.config import AIServiceSettings
from shared.enums import AITaskType, DataClassification
from shared.exceptions import ConfigurationError, UnauthorizedOperationError
from shared.schemas import KillswitchModel

from agent_core.llm.provider import ProviderCapabilities
from agent_core.llm.provider_registry import ProviderRegistry


class TaskRouteTarget(KillswitchModel):
    """Single configured provider + model target for a task."""

    provider_name: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    max_input_tokens: StrictInt = Field(default=6000, ge=256, le=200_000)
    max_output_tokens: StrictInt = Field(default=1500, ge=64, le=32_000)
    allowed_classifications: tuple[DataClassification, ...] = (
        DataClassification.PUBLIC,
        DataClassification.INTERNAL,
        DataClassification.RESTRICTED_SECURITY,
        DataClassification.SENSITIVE_SOURCE,
    )
    require_native_schema: StrictBool = False
    require_tool_calling: StrictBool = False


class TaskRouteConfig(KillswitchModel):
    """Primary and optional explicitly authorized failover targets for an AI task."""

    task_type: AITaskType
    primary: TaskRouteTarget
    failover_targets: list[TaskRouteTarget] = Field(default_factory=list)
    allow_failover: StrictBool = False
    max_total_attempts_across_providers: StrictInt = Field(default=3, ge=1, le=10)


class ModelRouter:
    """Resolves task routes, validates capabilities, and enforces data-classification rules."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        routes: dict[AITaskType, TaskRouteConfig] | None = None,
        default_provider: str = "offline_fixture",
        default_model: str = "fixture-investigator-v1",
        default_max_input_tokens: int = 6000,
        default_max_output_tokens: int = 1500,
        allow_failover: bool = False,
    ) -> None:
        self._registry = registry
        self._routes: dict[AITaskType, TaskRouteConfig] = routes or {}
        self._default_provider = default_provider
        self._default_model = default_model
        self._default_max_input_tokens = default_max_input_tokens
        self._default_max_output_tokens = default_max_output_tokens
        self._allow_failover = allow_failover

    @classmethod
    def from_settings(
        cls, settings: AIServiceSettings, *, registry: ProviderRegistry
    ) -> ModelRouter:
        """Build a router initialized cleanly from validated ``AIServiceSettings``."""
        model = (
            settings.llm_model
            if settings.llm_provider != "offline_fixture" or settings.llm_model != "unconfigured"
            else "fixture-investigator-v1"
        )
        default_target = TaskRouteTarget(
            provider_name=settings.llm_provider,
            model_name=model,
            max_input_tokens=settings.llm_max_input_tokens,
            max_output_tokens=settings.llm_max_output_tokens,
        )
        routes = {
            task: TaskRouteConfig(
                task_type=task,
                primary=default_target,
                allow_failover=settings.llm_allow_failover,
                max_total_attempts_across_providers=max(1, settings.llm_max_retries + 1),
            )
            for task in AITaskType
        }
        return cls(
            registry=registry,
            routes=routes,
            default_provider=settings.llm_provider,
            default_model=model,
            default_max_input_tokens=settings.llm_max_input_tokens,
            default_max_output_tokens=settings.llm_max_output_tokens,
            allow_failover=settings.llm_allow_failover,
        )

    def set_route(self, config: TaskRouteConfig) -> None:
        """Register or override the explicit route configuration for a task type."""
        self._routes[config.task_type] = config

    def get_route(self, task_type: AITaskType) -> TaskRouteConfig:
        """Return configured route for ``task_type``, or synthesize from router defaults."""
        if task_type in self._routes:
            return self._routes[task_type]
        return TaskRouteConfig(
            task_type=task_type,
            primary=TaskRouteTarget(
                provider_name=self._default_provider,
                model_name=self._default_model,
                max_input_tokens=self._default_max_input_tokens,
                max_output_tokens=self._default_max_output_tokens,
            ),
            allow_failover=self._allow_failover,
        )

    def resolve_candidate_targets(
        self,
        *,
        task_type: AITaskType,
        data_classification: DataClassification,
        require_tools: bool = False,
        require_native_schema: bool = False,
    ) -> tuple[list[TaskRouteTarget], int]:
        """Return ordered eligible targets (primary + explicitly allowed failover) and attempt cap.

        Never silently routes ``SENSITIVE_SOURCE`` or ``RESTRICTED_SECURITY`` data to a
        failover target that does not explicitly permit that classification.
        """
        route = self.get_route(task_type)
        candidates: list[TaskRouteTarget] = [route.primary]
        if route.allow_failover and route.failover_targets:
            for alt in route.failover_targets:
                if data_classification in alt.allowed_classifications:
                    candidates.append(alt)

        eligible: list[TaskRouteTarget] = []
        for idx, target in enumerate(candidates):
            if (
                (not target.model_name or target.model_name.lower() == "unconfigured")
                and target.provider_name != "offline_fixture"
            ):
                if idx == 0:
                    raise ConfigurationError(
                        f"Model name is unconfigured for task {task_type.value!r} on "
                        f"provider {target.provider_name!r}."
                    )
                continue

            if data_classification not in target.allowed_classifications:
                if idx == 0:
                    raise UnauthorizedOperationError(
                        f"Primary provider {target.provider_name!r} is not permitted for "
                        f"data classification {data_classification.value!r}."
                    )
                continue

            provider = self._registry.get(target.provider_name)
            caps: ProviderCapabilities = provider.get_capabilities()
            if (require_native_schema or target.require_native_schema) and not (
                caps.supports_native_schema
            ):
                if idx == 0 and target.require_native_schema:
                    raise ConfigurationError(
                        f"Provider {target.provider_name!r} lacks required native schema support."
                    )
                continue
            if (require_tools or target.require_tool_calling) and not caps.supports_tool_calling:
                if idx == 0 and (require_tools or target.require_tool_calling):
                    raise ConfigurationError(
                        f"Provider {target.provider_name!r} lacks required tool calling support."
                    )
                continue
            eligible.append(target)

        if not eligible:
            raise ConfigurationError(
                f"No eligible configured LLM provider target found for task {task_type.value!r}."
            )
        return eligible, route.max_total_attempts_across_providers
