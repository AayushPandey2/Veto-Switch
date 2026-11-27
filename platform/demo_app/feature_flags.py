"""Fail-closed local feature-flag adapter for isolated demonstrations."""

import os
from enum import StrEnum
from pathlib import Path
from typing import ClassVar

from demo_app.database import (
    get_demo_flag_override,
    get_demo_identity_flag_override,
)


class FeatureState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class FeatureFlagProvider:
    """Evaluate local demo flags or server-side Flagsmith flags."""

    ENVIRONMENT_VARIABLES: ClassVar[dict[str, str]] = {
        "search_v1": "KILLSWITCH_FLAG_SEARCH_V1",
        "search_v2": "KILLSWITCH_FLAG_SEARCH_V2",
        "files_v1": "KILLSWITCH_FLAG_FILES_V1",
        "files_v2": "KILLSWITCH_FLAG_FILES_V2",
    }

    def __init__(
        self,
        *,
        demo_mode: bool,
        allow_vulnerable_routes: bool,
        database_path: Path,
        adapter: str = "local",
        flagsmith_server_environment_key: str | None = None,
    ) -> None:
        self._demo_mode = demo_mode
        self._allow_vulnerable_routes = allow_vulnerable_routes
        self._database_path = database_path
        self._adapter = adapter
        self._flagsmith = None
        if adapter == "flagsmith" and flagsmith_server_environment_key:
            try:
                from flagsmith import Flagsmith
            except ImportError as exc:
                raise RuntimeError(
                    "Install platform/requirements.txt to use Flagsmith."
                ) from exc
            self._flagsmith = Flagsmith(
                environment_key=flagsmith_server_environment_key
            )

    def get_state(
        self,
        feature_name: str,
        *,
        identity: str | None = None,
    ) -> FeatureState:
        return self.get_states((feature_name,), identity=identity).get(
            feature_name,
            FeatureState.UNKNOWN,
        )

    def get_states(
        self,
        feature_names: tuple[str, ...] | list[str],
        *,
        identity: str | None = None,
    ) -> dict[str, FeatureState]:
        """Evaluate related flags using one Flagsmith request per identity."""
        names = tuple(dict.fromkeys(feature_names))
        valid_names = set(self.ENVIRONMENT_VARIABLES)
        states: dict[str, FeatureState] = {}
        sdk_flags = None

        if self._adapter == "flagsmith" and self._flagsmith is not None:
            try:
                sdk_flags = (
                    self._flagsmith.get_identity_flags(identity)
                    if identity is not None
                    else self._flagsmith.get_environment_flags()
                )
            except Exception:
                # Do not make a second request per flag after a transient failure.
                sdk_flags = None

        for feature_name in names:
            if feature_name not in valid_names:
                states[feature_name] = FeatureState.UNKNOWN
                continue

            if (
                feature_name in {"search_v1", "files_v1"}
                and (not self._demo_mode or not self._allow_vulnerable_routes)
            ):
                states[feature_name] = FeatureState.DISABLED
                continue

            if self._adapter == "flagsmith":
                if sdk_flags is None:
                    states[feature_name] = FeatureState.UNKNOWN
                    continue
                try:
                    enabled = sdk_flags.is_feature_enabled(feature_name)
                except Exception:
                    states[feature_name] = FeatureState.UNKNOWN
                else:
                    states[feature_name] = (
                        FeatureState.ENABLED if enabled else FeatureState.DISABLED
                    )
                continue

            states[feature_name] = self._get_local_state(feature_name, identity)

        return states

    def _get_local_state(
        self,
        feature_name: str,
        identity: str | None,
    ) -> FeatureState:
        variable = self.ENVIRONMENT_VARIABLES.get(feature_name)

        if variable is None:
            return FeatureState.UNKNOWN

        if (
            feature_name in {"search_v1", "files_v1"}
            and (not self._demo_mode or not self._allow_vulnerable_routes)
        ):
            return FeatureState.DISABLED

        if identity is not None:
            identity_override = get_demo_identity_flag_override(
                self._database_path,
                identity,
                feature_name,
            )
            if identity_override is not None:
                return FeatureState.ENABLED if identity_override else FeatureState.DISABLED

        override = get_demo_flag_override(self._database_path, feature_name)
        if override is not None:
            return FeatureState.ENABLED if override else FeatureState.DISABLED

        value = os.getenv(variable)

        if value is None:
            return FeatureState.UNKNOWN

        normalized = value.strip().lower()

        if normalized in {"1", "true", "enabled"}:
            return FeatureState.ENABLED

        if normalized in {"0", "false", "disabled"}:
            return FeatureState.DISABLED

        return FeatureState.UNKNOWN

    def is_enabled(self, feature_name: str, *, identity: str | None = None) -> bool:
        return self.get_state(feature_name, identity=identity) is FeatureState.ENABLED
