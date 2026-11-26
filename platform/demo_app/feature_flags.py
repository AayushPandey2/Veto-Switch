"""Fail-closed local feature-flag adapter for isolated demonstrations."""

import os
from enum import StrEnum
from typing import ClassVar


class FeatureState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class LocalFeatureFlagProvider:
    """Read explicitly configured local flags without remote privileges."""

    ENVIRONMENT_VARIABLES: ClassVar[dict[str, str]] = {
        "search_v1": "KILLSWITCH_FLAG_SEARCH_V1",
        "search_v2": "KILLSWITCH_FLAG_SEARCH_V2",
        "files_v1": "KILLSWITCH_FLAG_FILES_V1",
        "files_v2": "KILLSWITCH_FLAG_FILES_V2",
    }

    def __init__(self, *, demo_mode: bool, allow_vulnerable_routes: bool) -> None:
        self._demo_mode = demo_mode
        self._allow_vulnerable_routes = allow_vulnerable_routes

    def get_state(self, feature_name: str) -> FeatureState:
        variable = self.ENVIRONMENT_VARIABLES.get(feature_name)

        if variable is None:
            return FeatureState.UNKNOWN

        if (
            feature_name in {"search_v1", "files_v1"}
            and (not self._demo_mode or not self._allow_vulnerable_routes)
        ):
            return FeatureState.DISABLED

        value = os.getenv(variable)

        if value is None:
            return FeatureState.UNKNOWN

        normalized = value.strip().lower()

        if normalized in {"1", "true", "enabled"}:
            return FeatureState.ENABLED

        if normalized in {"0", "false", "disabled"}:
            return FeatureState.DISABLED

        return FeatureState.UNKNOWN

    def is_enabled(self, feature_name: str) -> bool:
        return self.get_state(feature_name) is FeatureState.ENABLED
