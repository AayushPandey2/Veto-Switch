"""Tests verifying clean module imports without live credentials or stdlib shadowing."""

from __future__ import annotations

import importlib
import platform

import pytest


@pytest.mark.unit
@pytest.mark.parametrize(
    "module_name",
    [
        "shared",
        "shared.constants",
        "shared.enums",
        "shared.exceptions",
        "shared.identifiers",
        "shared.serialization",
        "shared.validation",
        "shared.schemas",
        "shared.artifacts",
        "shared.logging_config",
        "shared.config",
        "shared.contracts",
        "shared.fixtures",
        "shared.fixtures.loader",
        "agent_core",
        "remediation",
    ],
)
def test_all_foundational_modules_import_without_credentials(module_name: str) -> None:
    """Scenario 1 & 24: Every foundational module imports cleanly offline."""
    mod = importlib.import_module(module_name)
    assert mod is not None


@pytest.mark.unit
def test_stdlib_platform_not_shadowed() -> None:
    """Top-level platform/ directory must never shadow Python's built-in platform module."""
    assert hasattr(platform, "python_version")
    assert callable(platform.python_version)
    assert "Veto-Switch/platform/__init__.py" not in (getattr(platform, "__file__", "") or "")
