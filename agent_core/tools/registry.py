"""Registry of strictly read-only, scoped investigation tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel
from shared.enums import AITaskType, DataClassification
from shared.exceptions import ConfigurationError, UnauthorizedOperationError

from agent_core.tools.schemas import (
    GetAdvisoryContextToolInput,
    GetApplicationManifestToolInput,
    GetDependencyMetadataToolInput,
    GetEvidenceSummaryToolInput,
    GetFeatureRegistryToolInput,
    GetFindingToolInput,
    GetSourceExcerptToolInput,
    ToolAvailability,
    ToolDefinition,
    ToolSideEffectClass,
)

ToolHandlerFn = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]

FORBIDDEN_TOOL_SUBSTRINGS: tuple[str, ...] = (
    "shell",
    "bash",
    "cmd",
    "exec",
    "eval",
    "subprocess",
    "write",
    "edit",
    "delete",
    "mutate",
    "toggle",
    "enable_flag",
    "disable_flag",
    "flag_update",
    "deploy",
    "approve",
    "secret",
    "credential",
    "password",
    "token_fetch",
    "fetch_url",
    "http_post",
    "scan",
    "exploit",
    "patch_apply",
)


@dataclass
class RegisteredTool:
    """Registered read-only tool entry binding schema, metadata, and optional adapter."""

    definition: ToolDefinition
    input_model: type[BaseModel]
    handler: ToolHandlerFn | None = None


def is_forbidden_tool_name(tool_name: str) -> bool:
    """Return True if ``tool_name`` matches any privileged or unsafe tool pattern."""
    lowered = tool_name.strip().lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in FORBIDDEN_TOOL_SUBSTRINGS)


class ToolRegistry:
    """Allowlisted registry accepting ONLY validated read-only investigation tools."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(
        self,
        definition: ToolDefinition,
        *,
        input_model: type[BaseModel],
        handler: ToolHandlerFn | None = None,
        overwrite: bool = False,
    ) -> None:
        """Register a read-only tool after validating side-effect and forbidden-name rules."""
        if definition.side_effect != ToolSideEffectClass.READ_ONLY:
            raise UnauthorizedOperationError(
                f"Only read_only tools may be registered; got {definition.side_effect!r}."
            )
        if is_forbidden_tool_name(definition.name):
            raise UnauthorizedOperationError(
                f"Tool name {definition.name!r} violates forbidden tool policy.",
                context={"tool_name": definition.name},
            )
        if definition.name in self._tools and not overwrite:
            raise ConfigurationError(f"Tool {definition.name!r} is already registered.")
        self._tools[definition.name] = RegisteredTool(
            definition=definition,
            input_model=input_model,
            handler=handler,
        )

    def get(self, tool_name: str) -> RegisteredTool | None:
        return self._tools.get(tool_name)

    def list_definitions(
        self, *, task_type: AITaskType | None = None
    ) -> list[ToolDefinition]:
        defs = [entry.definition for entry in self._tools.values()]
        if task_type is not None:
            defs = [d for d in defs if task_type in d.allowed_task_types]
        return defs


def build_default_investigation_tool_registry(
    *,
    handlers: dict[str, ToolHandlerFn] | None = None,
    availability: ToolAvailability = ToolAvailability.FIXTURE_ONLY,
) -> ToolRegistry:
    """Build the standard allowlist of read-only investigation tools."""
    bound = handlers or {}
    reg = ToolRegistry()

    specs: list[tuple[str, str, type[BaseModel], DataClassification]] = [
        (
            "get_finding",
            "Retrieve normalized finding details scoped to the active incident.",
            GetFindingToolInput,
            DataClassification.RESTRICTED_SECURITY,
        ),
        (
            "get_evidence_summary",
            "Retrieve sanitized evidence artifact metadata and summary by artifact_id.",
            GetEvidenceSummaryToolInput,
            DataClassification.RESTRICTED_SECURITY,
        ),
        (
            "get_bounded_source_excerpt",
            "Retrieve an authorized bounded line range from an incident-relevant source file.",
            GetSourceExcerptToolInput,
            DataClassification.SENSITIVE_SOURCE,
        ),
        (
            "get_declared_feature_registry",
            "Read declared read-only feature flag names for the target environment.",
            GetFeatureRegistryToolInput,
            DataClassification.INTERNAL,
        ),
        (
            "get_dependency_metadata",
            "Read declared dependency version metadata for the affected component.",
            GetDependencyMetadataToolInput,
            DataClassification.INTERNAL,
        ),
        (
            "get_advisory_context",
            "Read supplied advisory summary for a referenced CVE identifier.",
            GetAdvisoryContextToolInput,
            DataClassification.PUBLIC,
        ),
        (
            "get_application_manifest",
            "Read declared read-only application component manifest.",
            GetApplicationManifestToolInput,
            DataClassification.INTERNAL,
        ),
    ]

    for name, desc, model_cls, classification in specs:
        handler = bound.get(name)
        tool_avail = availability if handler is not None else ToolAvailability.UNAVAILABLE
        reg.register(
            ToolDefinition(
                name=name,
                description=desc,
                input_schema=model_cls.model_json_schema(),
                output_schema={"type": "object"},
                allowed_task_types=(AITaskType.INVESTIGATION,),
                required_scope="incident_read",
                data_classification=classification,
                availability=tool_avail,
            ),
            input_model=model_cls,
            handler=handler,
        )
    return reg
