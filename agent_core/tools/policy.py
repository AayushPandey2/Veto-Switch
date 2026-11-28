"""Deterministic authorization, resource-scope, and call-budget policy for tools."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, StrictInt
from shared.enums import AITaskType
from shared.schemas import KillswitchModel
from shared.serialization import sha256_canonical
from shared.validation import validate_relative_safe_path

from agent_core.llm.observability import AIMetricsCollector
from agent_core.tools.registry import ToolRegistry, is_forbidden_tool_name
from agent_core.tools.schemas import ToolAvailability, ToolSideEffectClass


class ToolPolicyConfig(KillswitchModel):
    """Strict call, round, duplicate, byte, and time caps preventing unbounded agent loops."""

    max_calls_per_investigation: StrictInt = Field(default=5, ge=0, le=20)
    max_tool_rounds: StrictInt = Field(default=2, ge=0, le=5)
    max_repeated_identical_calls: StrictInt = Field(default=1, ge=1, le=3)
    max_total_execution_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    max_output_bytes_per_call: StrictInt = Field(default=8192, ge=128, le=65_536)
    max_total_output_bytes: StrictInt = Field(default=24_576, ge=256, le=200_000)


class ToolPolicyDecision(KillswitchModel):
    """Structured authorization decision produced outside the LLM."""

    allowed: bool
    reason_code: str
    message: str


class ToolPolicyEnforcer:
    """Enforces read-only allowlists, incident/path scoping, and bounded execution caps."""

    def __init__(
        self,
        *,
        incident_id: str,
        task_type: AITaskType,
        registry: ToolRegistry,
        config: ToolPolicyConfig | None = None,
        allowed_tool_names: set[str] | None = None,
        authorized_source_paths: set[str] | None = None,
        metrics: AIMetricsCollector | None = None,
    ) -> None:
        self._incident_id = incident_id
        self._task_type = task_type
        self._registry = registry
        self.config = config or ToolPolicyConfig()
        self._allowed_tool_names = allowed_tool_names
        self._authorized_source_paths = authorized_source_paths
        self._metrics = metrics
        self._call_count: int = 0
        self._total_output_bytes: int = 0
        self._seen_call_hashes: dict[str, int] = {}
        self.attempted_violations: int = 0
        self.executed_violations: int = 0

    def _deny(self, reason_code: str, message: str) -> ToolPolicyDecision:
        self.attempted_violations += 1
        if self._metrics is not None:
            self._metrics.tool_authorization_rejections += 1
        return ToolPolicyDecision(allowed=False, reason_code=reason_code, message=message)

    def evaluate_request(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        elapsed_seconds: float = 0.0,
        current_round: int = 1,
        now: datetime | None = None,
    ) -> ToolPolicyDecision:
        """Validate a single requested tool call before any adapter is invoked."""
        _ = now
        if is_forbidden_tool_name(tool_name):
            return self._deny(
                "FORBIDDEN_TOOL_REQUEST",
                f"Tool {tool_name!r} is strictly forbidden for AI execution.",
            )

        entry = self._registry.get(tool_name)
        if entry is None:
            return self._deny("UNKNOWN_TOOL", f"Tool {tool_name!r} is not in allowlist registry.")

        defn = entry.definition
        if defn.side_effect != ToolSideEffectClass.READ_ONLY:
            return self._deny(
                "NON_READ_ONLY_TOOL",
                f"Tool {tool_name!r} is not read_only.",
            )

        if (
            self._allowed_tool_names is not None
            and tool_name not in self._allowed_tool_names
        ):
            return self._deny(
                "TOOL_NOT_GRANTED_TO_REQUEST",
                f"Tool {tool_name!r} was not authorized for this investigation request.",
            )

        if self._task_type not in defn.allowed_task_types:
            return self._deny(
                "TOOL_TASK_UNAUTHORIZED",
                f"Tool {tool_name!r} is not permitted for task {self._task_type.value!r}.",
            )

        if defn.availability == ToolAvailability.UNAVAILABLE or entry.handler is None:
            return self._deny(
                "TOOL_UNAVAILABLE",
                f"Tool {tool_name!r} has no authorized backend adapter configured.",
            )

        # Scope & argument validation (independent of model text)
        if not isinstance(arguments, dict):
            return self._deny("INVALID_TOOL_ARGUMENTS", "Tool arguments must be a JSON object.")

        req_incident = arguments.get("incident_id")
        if req_incident is not None and req_incident != self._incident_id:
            return self._deny(
                "CROSS_INCIDENT_TOOL_ACCESS",
                f"Requested incident_id {req_incident!r} mismatches active incident "
                f"{self._incident_id!r}.",
            )

        try:
            normalized_args = {
                **arguments,
                "incident_id": arguments.get("incident_id") or self._incident_id,
            }
            parsed_input = entry.input_model.model_validate(normalized_args)
        except Exception as exc:
            return self._deny(
                "INVALID_TOOL_ARGUMENTS",
                f"Arguments failed schema validation for tool {tool_name!r}: {exc}",
            )

        # Path traversal & authorized file path check for source excerpts
        file_path = getattr(parsed_input, "file_path", None)
        if isinstance(file_path, str):
            try:
                safe_path = validate_relative_safe_path(file_path, field_name="file_path")
            except Exception as exc:
                return self._deny(
                    "UNSAFE_RESOURCE_PATH",
                    f"Unsafe source path rejected: {exc}",
                )
            if (
                self._authorized_source_paths is not None
                and safe_path not in self._authorized_source_paths
            ):
                return self._deny(
                    "UNAUTHORIZED_SOURCE_PATH",
                    f"File path {safe_path!r} is outside incident authorized paths.",
                )

        if current_round > self.config.max_tool_rounds:
            return self._deny(
                "TOOL_ROUND_LIMIT_EXCEEDED",
                f"Tool round {current_round} exceeds maximum ({self.config.max_tool_rounds}).",
            )
        if self._call_count >= self.config.max_calls_per_investigation:
            return self._deny(
                "TOOL_CALL_LIMIT_EXCEEDED",
                f"Maximum tool calls ({self.config.max_calls_per_investigation}) reached.",
            )
        if elapsed_seconds > self.config.max_total_execution_seconds:
            return self._deny(
                "TOOL_TIME_LIMIT_EXCEEDED",
                "Cumulative tool execution time budget exceeded.",
            )
        if self._total_output_bytes >= self.config.max_total_output_bytes:
            return self._deny(
                "TOOL_TOTAL_OUTPUT_LIMIT_EXCEEDED",
                "Cumulative tool output byte budget exceeded.",
            )

        call_sig = sha256_canonical({"tool": tool_name, "args": normalized_args})
        repeat_count = self._seen_call_hashes.get(call_sig, 0)
        if repeat_count >= self.config.max_repeated_identical_calls:
            return self._deny(
                "REPEATED_IDENTICAL_TOOL_CALL",
                f"Repeated identical call to {tool_name!r} blocked by policy.",
            )

        return ToolPolicyDecision(
            allowed=True, reason_code="ALLOWED", message="Tool request authorized."
        )

    def record_execution(
        self, *, tool_name: str, arguments: dict[str, Any], output_bytes: int
    ) -> None:
        """Record an authorized tool execution against remaining policy budgets."""
        normalized_args = {
            **arguments,
            "incident_id": arguments.get("incident_id") or self._incident_id,
        }
        call_sig = sha256_canonical({"tool": tool_name, "args": normalized_args})
        self._call_count += 1
        self._total_output_bytes += max(0, output_bytes)
        self._seen_call_hashes[call_sig] = self._seen_call_hashes.get(call_sig, 0) + 1
