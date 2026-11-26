"""Isolate local demo settings from the developer's shell environment."""

import pytest


@pytest.fixture(autouse=True)
def _isolate_demo_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in (
        "KILLSWITCH_DEMO_ENV",
        "KILLSWITCH_DEMO_MODE",
        "KILLSWITCH_ALLOW_VULNERABLE_ROUTES",
        "KILLSWITCH_DEMO_DATABASE",
        "KILLSWITCH_FLAG_SEARCH_V1",
        "KILLSWITCH_FLAG_SEARCH_V2",
        "KILLSWITCH_FLAG_FILES_V1",
        "KILLSWITCH_FLAG_FILES_V2",
    ):
        monkeypatch.delenv(variable, raising=False)
