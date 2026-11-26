"""Contract tests verifying trust and privilege separation boundaries."""

from __future__ import annotations

import pytest
from shared.config import AIServiceSettings, PlatformPrivilegedSettings


@pytest.mark.contract
def test_ai_settings_exclude_privileged_platform_credentials() -> None:
    ai_fields = set(AIServiceSettings.model_fields.keys())
    privileged_fields = set(PlatformPrivilegedSettings.model_fields.keys())
    assert ai_fields.isdisjoint(privileged_fields)
    for forbidden in (
        "flagsmith_management_token",
        "flagsmith_environment_key",
        "approval_signing_secret",
        "database_url",
    ):
        assert forbidden not in ai_fields
        assert forbidden in privileged_fields
