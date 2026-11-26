"""Category H tests: read-only tool registry, authorization policy, scoping, caps."""

from __future__ import annotations

from typing import Any

import pytest
from agent_core.llm.observability import AIMetricsCollector
from agent_core.llm.response import ToolCallRequest
from agent_core.tools.executor import BoundedToolExecutor
from agent_core.tools.policy import ToolPolicyConfig, ToolPolicyEnforcer
from agent_core.tools.registry import (
    ToolRegistry,
    build_default_investigation_tool_registry,
)
from agent_core.tools.schemas import ToolAvailability, ToolDefinition
from pydantic import BaseModel
from shared.enums import AITaskType
from shared.exceptions import UnauthorizedOperationError


class _DummyToolIn(BaseModel):
    incident_id: str


@pytest.mark.unit
def test_registry_blocks_forbidden_mutation_and_shell_tools() -> None:
    reg = ToolRegistry()
    for bad_name in ("shell_exec", "mutate_flag", "deploy_patch", "get_secret", "write_file"):
        with pytest.raises(UnauthorizedOperationError):
            reg.register(
                ToolDefinition(
                    name=bad_name,
                    description="Forbidden test tool",
                    input_schema=_DummyToolIn.model_json_schema(),
                    output_schema={"type": "object"},
                ),
                input_model=_DummyToolIn,
            )


@pytest.mark.unit
async def test_tool_executor_allows_scoped_readonly_and_truncates_oversized_output() -> None:
    async def _get_finding(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "incident_id": args["incident_id"],
            "finding_id": args["finding_id"],
            "token_secret": "Bearer synthetic_leak_9999999",
            "large_blob": "A" * 2000,
        }

    reg = build_default_investigation_tool_registry(
        handlers={"get_finding": _get_finding},
        availability=ToolAvailability.FIXTURE_ONLY,
    )
    metrics = AIMetricsCollector()
    policy = ToolPolicyEnforcer(
        incident_id="inc_t_01",
        task_type=AITaskType.INVESTIGATION,
        registry=reg,
        config=ToolPolicyConfig(max_output_bytes_per_call=512, max_calls_per_investigation=2),
        metrics=metrics,
    )
    executor = BoundedToolExecutor(
        incident_id="inc_t_01",
        task_type=AITaskType.INVESTIGATION,
        registry=reg,
        policy=policy,
    )

    res = await executor.execute(
        ToolCallRequest(
            call_id="c1",
            tool_name="get_finding",
            arguments={"incident_id": "inc_t_01", "finding_id": "fnd_01"},
        )
    )
    assert res.audit.allowed is True
    assert res.audit.executed is True
    assert res.audit.truncated is True
    assert res.audit.output_bytes <= 512
    assert res.data is not None
    assert "synthetic_leak_9999999" not in str(res.data)

    # Repeated identical call blocked
    dup_res = await executor.execute(
        ToolCallRequest(
            call_id="c2",
            tool_name="get_finding",
            arguments={"incident_id": "inc_t_01", "finding_id": "fnd_01"},
        )
    )
    assert dup_res.audit.allowed is False
    assert dup_res.audit.reason_code == "REPEATED_IDENTICAL_TOOL_CALL"


@pytest.mark.unit
async def test_tool_policy_rejects_unknown_cross_incident_traversal_and_cap() -> None:
    async def _source_handler(args: dict[str, Any]) -> dict[str, Any]:
        return {"code": "ok", "file": args["file_path"]}

    reg = build_default_investigation_tool_registry(
        handlers={"get_bounded_source_excerpt": _source_handler},
    )
    metrics = AIMetricsCollector()
    policy = ToolPolicyEnforcer(
        incident_id="inc_t_02",
        task_type=AITaskType.INVESTIGATION,
        registry=reg,
        config=ToolPolicyConfig(max_calls_per_investigation=1),
        authorized_source_paths={"app/search.py"},
        metrics=metrics,
    )
    executor = BoundedToolExecutor(
        incident_id="inc_t_02",
        task_type=AITaskType.INVESTIGATION,
        registry=reg,
        policy=policy,
    )

    # Unknown tool
    unk = await executor.execute(
        ToolCallRequest(call_id="c1", tool_name="random_tool", arguments={})
    )
    assert not unk.audit.allowed and unk.audit.reason_code == "UNKNOWN_TOOL"

    # Cross-incident access
    cross = await executor.execute(
        ToolCallRequest(
            call_id="c2",
            tool_name="get_bounded_source_excerpt",
            arguments={"incident_id": "inc_OTHER", "file_path": "app/search.py"},
        )
    )
    assert not cross.audit.allowed and cross.audit.reason_code == "CROSS_INCIDENT_TOOL_ACCESS"

    # Path traversal
    trav = await executor.execute(
        ToolCallRequest(
            call_id="c3",
            tool_name="get_bounded_source_excerpt",
            arguments={"incident_id": "inc_t_02", "file_path": "../../etc/passwd"},
        )
    )
    assert not trav.audit.allowed and trav.audit.reason_code == "UNSAFE_RESOURCE_PATH"

    # Valid call uses up max_calls=1, next distinct call hits cap
    ok = await executor.execute(
        ToolCallRequest(
            call_id="c4",
            tool_name="get_bounded_source_excerpt",
            arguments={"incident_id": "inc_t_02", "file_path": "app/search.py", "start_line": 1},
        )
    )
    assert ok.audit.allowed and ok.audit.executed

    capped = await executor.execute(
        ToolCallRequest(
            call_id="c5",
            tool_name="get_bounded_source_excerpt",
            arguments={"incident_id": "inc_t_02", "file_path": "app/search.py", "start_line": 20},
        )
    )
    assert not capped.audit.allowed and capped.audit.reason_code == "TOOL_CALL_LIMIT_EXCEEDED"
    assert metrics.tool_authorization_rejections == 4
