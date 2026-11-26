"""Bounded, sanitized executor implementing the 10-step Section 22 tool workflow."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from shared.enums import AITaskType
from shared.logging_config import redact_mapping, redact_text

from agent_core.llm.response import ToolCallRequest
from agent_core.tools.policy import ToolPolicyEnforcer
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.schemas import ToolExecutionResult, ToolInvocationAudit


def _bound_and_sanitize_output(
    raw_data: dict[str, Any],
    *,
    max_bytes: int,
) -> tuple[dict[str, Any], int, bool]:
    sanitized = redact_mapping(raw_data)
    encoded = json.dumps(sanitized, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(encoded) <= max_bytes:
        return sanitized, len(encoded), False

    # Deterministically bound oversized string fields without breaking JSON validity.
    trimmed: dict[str, Any] = {}
    remaining = max(64, max_bytes - 96)
    for k, v in sanitized.items():
        if isinstance(v, str) and len(v) > remaining:
            trimmed[k] = v[:remaining] + "...[TRUNCATED]"
        elif isinstance(v, list):
            trimmed[k] = v[:5]
        else:
            trimmed[k] = v
    trimmed["_truncated"] = True
    bounded_bytes = json.dumps(trimmed, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(bounded_bytes) > max_bytes:
        preview = redact_text(json.dumps(sanitized, sort_keys=True))[: max(32, max_bytes - 80)]
        minimal = {"_truncated": True, "preview": preview}
        minimal_bytes = json.dumps(minimal).encode("utf-8")
        return minimal, len(minimal_bytes), True
    return trimmed, len(bounded_bytes), True


class BoundedToolExecutor:
    """Executes validated read-only investigation tools under policy & byte limits."""

    def __init__(
        self,
        *,
        incident_id: str,
        task_type: AITaskType,
        registry: ToolRegistry,
        policy: ToolPolicyEnforcer,
    ) -> None:
        self._incident_id = incident_id
        self._task_type = task_type
        self._registry = registry
        self._policy = policy
        self._started_at = time.monotonic()

    async def execute(
        self,
        call: ToolCallRequest,
        *,
        current_round: int = 1,
    ) -> ToolExecutionResult:
        """Validate, authorize, execute with timeout, redact, bound, and audit a tool call."""
        elapsed = time.monotonic() - self._started_at
        decision = self._policy.evaluate_request(
            tool_name=call.tool_name,
            arguments=call.arguments,
            elapsed_seconds=elapsed,
            current_round=current_round,
        )
        if not decision.allowed:
            return ToolExecutionResult(
                audit=ToolInvocationAudit(
                    call_id=call.call_id,
                    tool_name=call.tool_name,
                    incident_id=self._incident_id,
                    task_type=self._task_type,
                    allowed=False,
                    executed=False,
                    reason_code=decision.reason_code,
                    sanitized_message=redact_text(decision.message),
                ),
                data=None,
            )

        entry = self._registry.get(call.tool_name)
        if entry is None or entry.handler is None:
            return ToolExecutionResult(
                audit=ToolInvocationAudit(
                    call_id=call.call_id,
                    tool_name=call.tool_name,
                    incident_id=self._incident_id,
                    task_type=self._task_type,
                    allowed=False,
                    executed=False,
                    reason_code="TOOL_UNAVAILABLE",
                    sanitized_message=f"Tool {call.tool_name!r} handler unavailable.",
                ),
                data=None,
            )
        normalized_args = {
            **call.arguments,
            "incident_id": call.arguments.get("incident_id") or self._incident_id,
        }
        validated_args = entry.input_model.model_validate(normalized_args).model_dump()

        remaining_total = max(0.05, self._policy.config.max_total_execution_seconds - elapsed)
        timeout = min(entry.definition.timeout_seconds, remaining_total)

        try:
            raw_output = await asyncio.wait_for(entry.handler(validated_args), timeout=timeout)
        except TimeoutError:
            return ToolExecutionResult(
                audit=ToolInvocationAudit(
                    call_id=call.call_id,
                    tool_name=call.tool_name,
                    incident_id=self._incident_id,
                    task_type=self._task_type,
                    allowed=True,
                    executed=True,
                    reason_code="TOOL_EXECUTION_TIMEOUT",
                    sanitized_message=f"Tool {call.tool_name!r} timed out.",
                ),
                data=None,
            )
        except Exception as exc:
            return ToolExecutionResult(
                audit=ToolInvocationAudit(
                    call_id=call.call_id,
                    tool_name=call.tool_name,
                    incident_id=self._incident_id,
                    task_type=self._task_type,
                    allowed=True,
                    executed=True,
                    reason_code="TOOL_EXECUTION_ERROR",
                    sanitized_message=redact_text(
                        f"Tool {call.tool_name!r} failed: {type(exc).__name__}"
                    ),
                ),
                data=None,
            )

        max_per_call = min(
            entry.definition.max_output_bytes,
            self._policy.config.max_output_bytes_per_call,
        )
        bounded_data, out_bytes, truncated = _bound_and_sanitize_output(
            raw_output, max_bytes=max_per_call
        )
        self._policy.record_execution(
            tool_name=call.tool_name,
            arguments=validated_args,
            output_bytes=out_bytes,
        )
        return ToolExecutionResult(
            audit=ToolInvocationAudit(
                call_id=call.call_id,
                tool_name=call.tool_name,
                incident_id=self._incident_id,
                task_type=self._task_type,
                allowed=True,
                executed=True,
                reason_code="TOOL_EXECUTED",
                sanitized_message=f"Read-only tool {call.tool_name!r} executed cleanly.",
                output_bytes=out_bytes,
                truncated=truncated,
            ),
            data=bounded_data,
        )
