"""Schemas for bounded, strictly read-only investigation tools and audit records."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, StrictBool, StrictInt
from shared.enums import AITaskType, DataClassification
from shared.identifiers import utc_now
from shared.schemas import KillswitchModel, UtcDatetime


class ToolSideEffectClass(StrEnum):
    """Side-effect classification; Investigator tools permit ONLY ``read_only``."""

    READ_ONLY = "read_only"


class ToolAvailability(StrEnum):
    """Explicit readiness state of a tool adapter."""

    LIVE = "live"
    FIXTURE_ONLY = "fixture_only"
    UNAVAILABLE = "unavailable"


class ToolDefinition(KillswitchModel):
    """Metadata, input/output schema, scope, and resource bounds for a read-only tool."""

    name: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(min_length=4, max_length=300)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    allowed_task_types: tuple[AITaskType, ...] = (AITaskType.INVESTIGATION,)
    required_scope: str = Field(default="incident_read", min_length=1)
    timeout_seconds: float = Field(default=3.0, gt=0.0, le=30.0)
    max_output_bytes: StrictInt = Field(default=8192, ge=128, le=65_536)
    data_classification: DataClassification = DataClassification.RESTRICTED_SECURITY
    side_effect: Literal[ToolSideEffectClass.READ_ONLY] = ToolSideEffectClass.READ_ONLY
    availability: ToolAvailability = ToolAvailability.FIXTURE_ONLY

    def to_function_declaration(self) -> dict[str, Any]:
        """Serialize definition for model tool declarations."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.input_schema,
        }


class ToolInvocationAudit(KillswitchModel):
    """Immutable audit record emitted for every allowed or rejected tool call."""

    call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    task_type: AITaskType
    allowed: StrictBool
    executed: StrictBool = False
    reason_code: str = Field(min_length=1)
    sanitized_message: str = Field(min_length=1)
    output_bytes: StrictInt = Field(default=0, ge=0)
    truncated: StrictBool = False
    timestamp: UtcDatetime = Field(default_factory=utc_now)


class ToolExecutionResult(KillswitchModel):
    """Bounded sanitized output returned by ``BoundedToolExecutor``."""

    audit: ToolInvocationAudit
    data: dict[str, Any] | None = None


class IncidentScopedToolInput(BaseModel):
    """Base input schema requiring explicit incident binding on read-only tool requests."""

    incident_id: str = Field(min_length=4, max_length=128)


class GetFindingToolInput(IncidentScopedToolInput):
    finding_id: str = Field(min_length=4, max_length=128)


class GetEvidenceSummaryToolInput(IncidentScopedToolInput):
    artifact_id: str = Field(min_length=4, max_length=128)


class GetSourceExcerptToolInput(IncidentScopedToolInput):
    file_path: str = Field(min_length=1, max_length=256)
    start_line: StrictInt = Field(default=1, ge=1, le=50_000)
    end_line: StrictInt = Field(default=60, ge=1, le=50_000)


class GetFeatureRegistryToolInput(IncidentScopedToolInput):
    environment: str = Field(min_length=1, max_length=64)


class GetDependencyMetadataToolInput(IncidentScopedToolInput):
    component: str = Field(min_length=1, max_length=128)


class GetAdvisoryContextToolInput(IncidentScopedToolInput):
    cve_id: str = Field(min_length=4, max_length=64)


class GetApplicationManifestToolInput(IncidentScopedToolInput):
    component: str | None = Field(default=None, max_length=128)
