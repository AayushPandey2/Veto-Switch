"""Contract tests verifying abstract service protocol definitions and safety boundaries."""

from __future__ import annotations

import inspect

import pytest
from shared.contracts import (
    ApprovalReader,
    DeploymentStateReader,
    EventRepository,
    EvidenceRepository,
    FeatureStateReader,
    IncidentRepository,
    LLMProvider,
    PatchTestRunner,
    SecurityVerifier,
    TelemetryReader,
)


@pytest.mark.contract
def test_feature_state_reader_exposes_only_read_methods() -> None:
    """Scenario 23: FeatureStateReader exposes zero privileged mutation methods."""
    public_methods = {
        name
        for name, member in inspect.getmembers(FeatureStateReader, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    expected_read_methods = {
        "get_feature_state",
        "list_declared_features",
        "get_environment_metadata",
        "get_targeting_configuration",
    }
    assert public_methods == expected_read_methods
    forbidden_verbs = ("set", "update", "toggle", "enable", "disable", "mutate", "write", "delete")
    for method_name in public_methods:
        assert not any(verb in method_name.lower() for verb in forbidden_verbs)


@pytest.mark.contract
def test_llm_provider_and_patch_runner_expose_no_arbitrary_execution() -> None:
    llm_methods = {
        name
        for name, _ in inspect.getmembers(LLMProvider, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    assert llm_methods == {"generate_structured"}

    runner_methods = {
        name
        for name, _ in inspect.getmembers(PatchTestRunner, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    assert runner_methods == {
        "submit_patch_test",
        "get_test_run_status",
        "get_patch_test_result",
    }


@pytest.mark.contract
@pytest.mark.parametrize(
    "protocol_cls",
    [
        LLMProvider,
        IncidentRepository,
        EventRepository,
        EvidenceRepository,
        FeatureStateReader,
        SecurityVerifier,
        PatchTestRunner,
        TelemetryReader,
        ApprovalReader,
        DeploymentStateReader,
    ],
)
def test_all_service_protocols_are_runtime_checkable(protocol_cls: type) -> None:
    assert getattr(protocol_cls, "_is_runtime_protocol", False) is True
