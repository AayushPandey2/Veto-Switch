"""Server-only Flagsmith Management API adapter for approved flag changes."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlencode, urljoin, urlparse

import httpx


class FlagsmithIntegrationError(RuntimeError):
    """A safe-to-report Flagsmith failure without request or credential data."""

    def __init__(self, code: str, *, status_code: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class FlagsmithManagementClient:
    """Read and update environment-level feature states on the server only."""

    def __init__(
        self,
        *,
        environment_key: str,
        management_token: str,
        api_url: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        parsed = urlparse(api_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("Flagsmith Management API must use HTTPS.")
        self._api_url = api_url.rstrip("/")
        self._api_host = parsed.netloc.lower()
        self._environment_key = quote(environment_key, safe="")
        self._headers = {"Authorization": f"Api-Key {management_token}"}
        self._timeout = timeout_seconds

    def read_flags(
        self,
        names: tuple[str, ...],
        *,
        allow_missing: bool = False,
    ) -> dict[str, bool | None]:
        feature_names = self._read_feature_names()
        states = self._read_environment_states()
        result: dict[str, bool] = {}
        for name in names:
            matches = [
                state
                for state in states
                if self._feature_name(state, feature_names) == name
            ]
            matches = [state for state in matches if self._is_environment_default(state)]
            if not matches and allow_missing:
                result[name] = None
                continue
            if len(matches) != 1:
                raise FlagsmithIntegrationError(
                    "flag_missing_or_ambiguous" if not matches else "flag_state_ambiguous"
                )
            enabled = matches[0].get("enabled")
            if not isinstance(enabled, bool):
                raise FlagsmithIntegrationError("flag_state_invalid")
            result[name] = enabled
        return result

    def set_flag_enabled(self, name: str, enabled: bool) -> bool:
        environment = self._read_environment()
        feature_names = self._read_feature_names(environment)
        states = self._read_environment_states()
        matches = [
            state
            for state in states
            if self._feature_name(state, feature_names) == name
        ]
        matches = [state for state in matches if self._is_environment_default(state)]
        if len(matches) != 1:
            raise FlagsmithIntegrationError(
                "flag_missing_or_ambiguous" if not matches else "flag_state_ambiguous"
            )
        feature_state_id = matches[0].get("id")
        if not isinstance(feature_state_id, (str, int)):
            raise FlagsmithIntegrationError("flag_state_invalid")

        if matches[0].get("enabled") is enabled:
            return enabled

        if environment.get("use_v2_feature_versioning") is True:
            self._set_versioned_flag_enabled(
                environment=environment,
                feature_state=matches[0],
                enabled=enabled,
            )
        else:
            url = (
                f"{self._api_url}/environments/{self._environment_key}"
                f"/featurestates/{quote(str(feature_state_id), safe='')}/"
            )
            self._request("PATCH", url, json={"enabled": enabled})
        readback = self.read_flags((name,))[name]
        if readback is not enabled:
            raise FlagsmithIntegrationError("flag_readback_failed")
        return readback

    def _set_versioned_flag_enabled(
        self,
        *,
        environment: dict,
        feature_state: dict,
        enabled: bool,
    ) -> None:
        environment_id = environment.get("id")
        if not isinstance(environment_id, int) or isinstance(environment_id, bool):
            raise FlagsmithIntegrationError("flagsmith_environment_response_invalid")

        feature = feature_state.get("feature")
        feature_id = feature.get("id") if isinstance(feature, dict) else feature
        version_id = feature_state.get("environment_feature_version")
        feature_state_id = feature_state.get("id")
        if (
            not isinstance(feature_id, (str, int))
            or isinstance(feature_id, bool)
            or not isinstance(version_id, str)
            or not isinstance(feature_state_id, (str, int))
        ):
            raise FlagsmithIntegrationError("flagsmith_versioned_state_invalid")

        version_states_url = (
            f"{self._api_url}/environments/{quote(str(environment_id), safe='')}"
            f"/features/{quote(str(feature_id), safe='')}"
            f"/versions/{quote(version_id, safe='')}/featurestates/"
        )
        version_states = self._request("GET", version_states_url)
        if not isinstance(version_states, list) or any(
            not isinstance(state, dict) for state in version_states
        ):
            raise FlagsmithIntegrationError("flagsmith_version_state_list_invalid")

        default_states = [
            state
            for state in version_states
            if self._is_environment_default(state)
        ]
        if (
            len(default_states) != 1
            or str(default_states[0].get("id")) != str(feature_state_id)
        ):
            raise FlagsmithIntegrationError("flagsmith_versioned_state_ambiguous")

        current = default_states[0]
        feature_state_value = current.get("feature_state_value")
        if not isinstance(feature_state_value, dict):
            raise FlagsmithIntegrationError("flagsmith_versioned_state_invalid")

        # A v2 environment publishes immutable snapshots. Create and publish a
        # new snapshot that changes only `enabled`, carrying the value and any
        # multivariate allocations forward unchanged.
        state_update = {
            "enabled": enabled,
            "feature_state_value": feature_state_value,
            "feature_segment": current.get("feature_segment"),
        }
        multivariate_values = current.get("multivariate_feature_state_values")
        if isinstance(multivariate_values, list):
            state_update["multivariate_feature_state_values"] = [
                {key: value for key, value in item.items() if key != "id"}
                for item in multivariate_values
                if isinstance(item, dict)
            ]

        create_version_url = (
            f"{self._api_url}/environments/{quote(str(environment_id), safe='')}"
            f"/features/{quote(str(feature_id), safe='')}/versions/"
        )
        published_version = self._request(
            "POST",
            create_version_url,
            json={
                "feature_states_to_update": [state_update],
                "publish_immediately": True,
            },
        )
        if (
            not isinstance(published_version, dict)
            or published_version.get("published") is not True
            or published_version.get("is_live") is not True
        ):
            raise FlagsmithIntegrationError("flagsmith_version_publish_unconfirmed")

    def read_identity_feature_override(
        self,
        identifier: str,
        feature_name: str,
    ) -> bool | None:
        """Return an explicit identity override, or None when it inherits."""
        if self._uses_v2_feature_versioning():
            return self.read_identity_feature_overrides((identifier,), feature_name)[identifier]
        identity_id = self._identity_id(identifier, create=False)
        feature_names = self._read_feature_names()
        feature_id = self._feature_id(feature_name, feature_names)
        state = self._identity_feature_state(identity_id, feature_id, feature_names)
        return None if state is None else bool(state["enabled"])

    def read_identity_feature_overrides(
        self,
        identifiers: tuple[str, ...],
        feature_name: str,
    ) -> dict[str, bool | None]:
        feature_names = self._read_feature_names()
        feature_id = self._feature_id(feature_name, feature_names)
        if self._uses_v2_feature_versioning():
            identity_ids = self._edge_identities_by_identifier(identifiers)
            result: dict[str, bool | None] = {identifier: None for identifier in identifiers}
            existing = [
                (identifier, identity_ids[identifier])
                for identifier in identifiers
                if identifier in identity_ids
            ]

            def read_state(item: tuple[str, str]) -> tuple[str, bool | None]:
                identifier, identity_uuid = item
                state = self._edge_identity_feature_state(identity_uuid, feature_id)
                return identifier, None if state is None else state["enabled"]

            if existing:
                with ThreadPoolExecutor(max_workers=min(4, len(existing))) as executor:
                    for identifier, enabled in executor.map(read_state, existing):
                        result[identifier] = enabled
            return result

        identity_ids = self._identities_by_identifier()
        result: dict[str, bool | None] = {identifier: None for identifier in identifiers}
        existing = [
            (identifier, identity_ids[identifier])
            for identifier in identifiers
            if identifier in identity_ids
        ]

        def read_state(item: tuple[str, str | int]) -> tuple[str, bool | None]:
            identifier, identity_id = item
            state = self._identity_feature_state(identity_id, feature_id, feature_names)
            return identifier, None if state is None else state["enabled"]

        if existing:
            # Keep concurrency bounded while avoiding one serial API round trip
            # per seeded demo identity during rollout planning/readback.
            with ThreadPoolExecutor(max_workers=min(4, len(existing))) as executor:
                for identifier, enabled in executor.map(read_state, existing):
                    result[identifier] = enabled
        return result

    def apply_identity_feature_overrides(
        self,
        values: dict[str, bool | None],
        feature_name: str,
    ) -> dict[str, bool | None]:
        """Apply a set of approved per-identity changes and verify exact readback."""
        feature_names = self._read_feature_names()
        feature_id = self._feature_id(feature_name, feature_names)
        if self._uses_v2_feature_versioning():
            identities = self._edge_identities_by_identifier(tuple(values))
            for identifier, enabled in values.items():
                if not identifier or len(identifier) > 128:
                    raise FlagsmithIntegrationError("identity_identifier_invalid")
                identity_uuid = identities.get(identifier)
                if identity_uuid is None:
                    if enabled is None:
                        continue
                    raise FlagsmithIntegrationError("edge_identity_not_found")

                state = self._edge_identity_feature_state(identity_uuid, feature_id)
                if enabled is None:
                    if state is not None:
                        self._delete_edge_identity_feature_state(
                            identity_uuid, feature_id, state["uuid"]
                        )
                    continue
                if state is not None and state["enabled"] is enabled:
                    continue

                url = self._edge_identity_feature_collection_url(identity_uuid)
                if state is None:
                    self._request(
                        "POST", url, json={"feature": feature_id, "enabled": enabled}
                    )
                else:
                    self._request(
                        "PUT",
                        self._edge_identity_feature_state_url(identity_uuid, state["uuid"]),
                        json={
                            "feature": feature_id,
                            "enabled": enabled,
                            **{
                                key: state[key]
                                for key in (
                                    "feature_state_value",
                                    "multivariate_feature_state_values",
                                )
                                if key in state
                            },
                        },
                    )

            readback = self.read_identity_feature_overrides(tuple(values), feature_name)
            if readback != values:
                raise FlagsmithIntegrationError("identity_override_readback_failed")
            return readback

        identities = self._identities_by_identifier()
        for identifier, enabled in values.items():
            if not identifier or len(identifier) > 128:
                raise FlagsmithIntegrationError("identity_identifier_invalid")
            identity_id = identities.get(identifier)
            if identity_id is None and enabled is None:
                continue
            if identity_id is None:
                created = self._request(
                    "POST",
                    f"{self._api_url}/environments/{self._environment_key}/identities/",
                    json={"identifier": identifier},
                )
                if not isinstance(created, dict) or not isinstance(created.get("id"), (str, int)):
                    raise FlagsmithIntegrationError("identity_create_response_invalid")
                identity_id = created["id"]
                identities[identifier] = identity_id

            state = self._identity_feature_state(identity_id, feature_id, feature_names)
            if enabled is None:
                if state is not None:
                    self._delete_identity_feature_state(
                        identity_id,
                        feature_id,
                        feature_names,
                        state["id"],
                    )
                continue
            if state is not None and state["enabled"] is enabled:
                continue
            if state is None:
                self._request(
                    "POST",
                    self._identity_feature_collection_url(identity_id),
                    json={"feature": feature_id, "enabled": enabled},
                )
            else:
                self._request(
                    "PATCH",
                    self._identity_feature_state_url(identity_id, state["id"]),
                    json={"enabled": enabled},
                )
        readback = self.read_identity_feature_overrides(tuple(values), feature_name)
        if readback != values:
            raise FlagsmithIntegrationError("identity_override_readback_failed")
        return readback

    def set_identity_feature_override(
        self,
        identifier: str,
        feature_name: str,
        enabled: bool,
    ) -> bool:
        """Create or update one Flagsmith identity override and read it back."""
        if self._uses_v2_feature_versioning():
            result = self.apply_identity_feature_overrides(
                {identifier: enabled}, feature_name
            )
            return result[identifier] is enabled
        identity_id = self._identity_id(identifier, create=True)
        feature_names = self._read_feature_names()
        feature_id = self._feature_id(feature_name, feature_names)
        state = self._identity_feature_state(identity_id, feature_id, feature_names)
        if state is not None and state["enabled"] is enabled:
            return enabled
        if state is None:
            self._request(
                "POST",
                self._identity_feature_collection_url(identity_id),
                json={"feature": feature_id, "enabled": enabled},
            )
        else:
            self._request(
                "PATCH",
                self._identity_feature_state_url(identity_id, state["id"]),
                json={"enabled": enabled},
            )
        readback = self.read_identity_feature_override(identifier, feature_name)
        if readback is not enabled:
            raise FlagsmithIntegrationError("identity_override_readback_failed")
        return readback

    def delete_identity_feature_override(
        self,
        identifier: str,
        feature_name: str,
    ) -> None:
        """Remove an explicit override so the identity inherits environment state."""
        if self._uses_v2_feature_versioning():
            identity_uuid = self._edge_identities_by_identifier((identifier,)).get(identifier)
            if identity_uuid is None:
                return
            feature_names = self._read_feature_names()
            feature_id = self._feature_id(feature_name, feature_names)
            state = self._edge_identity_feature_state(identity_uuid, feature_id)
            if state is not None:
                self._delete_edge_identity_feature_state(
                    identity_uuid, feature_id, state["uuid"]
                )
            if self.read_identity_feature_override(identifier, feature_name) is not None:
                raise FlagsmithIntegrationError("identity_override_readback_failed")
            return
        identity_id = self._identity_id(identifier, create=False)
        feature_names = self._read_feature_names()
        feature_id = self._feature_id(feature_name, feature_names)
        state = self._identity_feature_state(identity_id, feature_id, feature_names)
        if state is None:
            return
        self._delete_identity_feature_state(
            identity_id,
            feature_id,
            feature_names,
            state["id"],
        )
        if self.read_identity_feature_override(identifier, feature_name) is not None:
            raise FlagsmithIntegrationError("identity_override_readback_failed")

    def _delete_identity_feature_state(
        self,
        identity_id: str | int,
        feature_id: str | int,
        feature_names: dict[str, str],
        state_id: str | int,
    ) -> None:
        """Delete an identity override, accepting 404 only after absence is confirmed."""
        try:
            self._request(
                "DELETE",
                self._identity_feature_state_url(identity_id, state_id),
            )
        except FlagsmithIntegrationError as exc:
            if exc.status_code != 404:
                raise
            # Another operator or process may have cleared this override after our
            # initial list read. Treat that race as an idempotent delete only when
            # the identity's current feature-state list confirms it is gone.
            if self._identity_feature_state(identity_id, feature_id, feature_names) is not None:
                raise exc

    def _read_identities(self) -> list[dict]:
        next_url: str | None = (
            f"{self._api_url}/environments/{self._environment_key}/identities/"
        )
        identities: list[dict] = []
        pages = 0
        while next_url is not None:
            pages += 1
            if pages > 20:
                raise FlagsmithIntegrationError("identity_list_page_limit")
            self._validate_next_url(next_url)
            payload = self._request("GET", next_url)
            if isinstance(payload, list):
                page = payload
                next_link = None
            elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
                page = payload["results"]
                next_link = payload.get("next")
            else:
                raise FlagsmithIntegrationError("identity_list_response_invalid")
            if any(not isinstance(item, dict) for item in page):
                raise FlagsmithIntegrationError("identity_list_response_invalid")
            identities.extend(page)
            next_url = urljoin(next_url, next_link) if isinstance(next_link, str) else None
        return identities

    def _uses_v2_feature_versioning(self) -> bool:
        environment = self._read_environment()
        return environment.get("use_v2_feature_versioning") is True

    def _edge_identities_by_identifier(
        self,
        identifiers: tuple[str, ...],
    ) -> dict[str, str]:
        """Return versioned edge identity UUIDs for the requested identifiers."""
        collection_url = (
            f"{self._api_url}/environments/{self._environment_key}/edge-identities/"
        )
        next_url: str | None = f"{collection_url}?{urlencode({'page_size': 100})}"
        found: dict[str, str] = {}
        requested = set(identifiers)
        cursors: set[str] = set()
        pages = 0
        while next_url is not None:
            pages += 1
            if pages > 20:
                raise FlagsmithIntegrationError("edge_identity_list_page_limit")
            self._validate_next_url(next_url)
            payload = self._request("GET", next_url)
            if isinstance(payload, list):
                page = payload
                cursor = None
            elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
                page = payload["results"]
                cursor = payload.get("last_evaluated_key")
            else:
                raise FlagsmithIntegrationError("edge_identity_list_response_invalid")
            if any(not isinstance(item, dict) for item in page):
                raise FlagsmithIntegrationError("edge_identity_list_response_invalid")
            for item in page:
                identifier = item.get("identifier")
                identity_uuid = item.get("identity_uuid")
                if identifier not in requested:
                    continue
                if not isinstance(identity_uuid, str) or not identity_uuid:
                    raise FlagsmithIntegrationError("edge_identity_response_invalid")
                if identifier in found and found[identifier] != identity_uuid:
                    raise FlagsmithIntegrationError("identity_ambiguous")
                found[identifier] = identity_uuid
            if isinstance(cursor, str) and cursor:
                if cursor in cursors:
                    raise FlagsmithIntegrationError("edge_identity_list_cursor_invalid")
                cursors.add(cursor)
                next_url = f"{collection_url}?{urlencode({'page_size': 100, 'last_evaluated_key': cursor})}"
            else:
                next_url = None
        return found

    def _edge_identity_feature_state(
        self,
        identity_uuid: str,
        feature_id: str | int,
    ) -> dict | None:
        payload = self._request(
            "GET", self._edge_identity_feature_collection_url(identity_uuid)
        )
        if isinstance(payload, list):
            states = payload
        elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
            states = payload["results"]
        else:
            raise FlagsmithIntegrationError("edge_identity_featurestate_response_invalid")
        matches = [
            state for state in states
            if isinstance(state, dict) and str(state.get("feature")) == str(feature_id)
        ]
        if len(matches) > 1:
            raise FlagsmithIntegrationError("identity_featurestate_ambiguous")
        if not matches:
            return None
        state = matches[0]
        state_uuid = state.get("featurestate_uuid")
        enabled = state.get("enabled")
        if not isinstance(state_uuid, str) or not isinstance(enabled, bool):
            raise FlagsmithIntegrationError("edge_identity_featurestate_invalid")
        return {
            "uuid": state_uuid,
            "enabled": enabled,
            **{
                key: state[key]
                for key in (
                    "feature_state_value",
                    "multivariate_feature_state_values",
                )
                if key in state
            },
        }

    def _delete_edge_identity_feature_state(
        self,
        identity_uuid: str,
        feature_id: str | int,
        state_uuid: str,
    ) -> None:
        try:
            self._request(
                "DELETE", self._edge_identity_feature_state_url(identity_uuid, state_uuid)
            )
        except FlagsmithIntegrationError as exc:
            if exc.status_code != 404:
                raise
            if self._edge_identity_feature_state(identity_uuid, feature_id) is not None:
                raise exc

    def _edge_identity_feature_collection_url(self, identity_uuid: str) -> str:
        return (
            f"{self._api_url}/environments/{self._environment_key}/edge-identities/"
            f"{quote(identity_uuid, safe='')}/edge-featurestates/"
        )

    def _edge_identity_feature_state_url(self, identity_uuid: str, state_uuid: str) -> str:
        return f"{self._edge_identity_feature_collection_url(identity_uuid)}{quote(state_uuid, safe='')}/"

    def _identity_id(self, identifier: str, *, create: bool) -> str | int:
        if not identifier or len(identifier) > 128:
            raise FlagsmithIntegrationError("identity_identifier_invalid")
        matches = [
            item for item in self._read_identities()
            if item.get("identifier") == identifier
        ]
        if len(matches) > 1:
            raise FlagsmithIntegrationError("identity_ambiguous")
        if matches:
            identity_id = matches[0].get("id")
            if isinstance(identity_id, (str, int)):
                return identity_id
            raise FlagsmithIntegrationError("identity_response_invalid")
        if not create:
            raise FlagsmithIntegrationError("identity_not_found")
        url = f"{self._api_url}/environments/{self._environment_key}/identities/"
        created = self._request("POST", url, json={"identifier": identifier})
        if isinstance(created, dict):
            identity_id = created.get("id")
            if created.get("identifier") == identifier and isinstance(identity_id, (str, int)):
                return identity_id
        raise FlagsmithIntegrationError("identity_create_response_invalid")

    def _identities_by_identifier(self) -> dict[str, str | int]:
        identities: dict[str, str | int] = {}
        for item in self._read_identities():
            identifier = item.get("identifier")
            identity_id = item.get("id")
            if not isinstance(identifier, str):
                continue
            if not isinstance(identity_id, (str, int)):
                raise FlagsmithIntegrationError("identity_response_invalid")
            if identifier in identities and identities[identifier] != identity_id:
                raise FlagsmithIntegrationError("identity_ambiguous")
            identities[identifier] = identity_id
        return identities

    @staticmethod
    def _feature_id(feature_name: str, names_by_id: dict[str, str]) -> str | int:
        matches = [feature_id for feature_id, name in names_by_id.items() if name == feature_name]
        if len(matches) != 1:
            raise FlagsmithIntegrationError(
                "flag_missing_or_ambiguous" if not matches else "flag_state_ambiguous"
            )
        return int(matches[0]) if matches[0].isdigit() else matches[0]

    def _identity_feature_state(
        self,
        identity_id: str | int,
        feature_id: str | int,
        feature_names: dict[str, str],
    ) -> dict | None:
        url = (
            f"{self._api_url}/environments/{self._environment_key}"
            f"/identities/{quote(str(identity_id), safe='')}/featurestates/"
        )
        payload = self._request("GET", url)
        if isinstance(payload, list):
            states = payload
        elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
            states = payload["results"]
        else:
            raise FlagsmithIntegrationError("identity_featurestate_response_invalid")
        matches = [
            state for state in states
            if isinstance(state, dict)
            and self._feature_name(state, feature_names) == feature_names.get(str(feature_id))
        ]
        if len(matches) > 1:
            raise FlagsmithIntegrationError("identity_featurestate_ambiguous")
        if not matches:
            return None
        enabled = matches[0].get("enabled")
        state_id = matches[0].get("id")
        if not isinstance(enabled, bool) or not isinstance(state_id, (str, int)):
            raise FlagsmithIntegrationError("identity_featurestate_invalid")
        return {"id": state_id, "enabled": enabled}

    def _identity_feature_collection_url(self, identity_id: str | int) -> str:
        return (
            f"{self._api_url}/environments/{self._environment_key}"
            f"/identities/{quote(str(identity_id), safe='')}/featurestates/"
        )

    def _identity_feature_state_url(self, identity_id: str | int, state_id: str | int) -> str:
        return f"{self._identity_feature_collection_url(identity_id)}{quote(str(state_id), safe='')}/"

    def _read_environment_states(self) -> list[dict]:
        next_url: str | None = (
            f"{self._api_url}/environments/{self._environment_key}/featurestates/"
        )
        states: list[dict] = []
        pages = 0

        while next_url is not None:
            pages += 1
            if pages > 20:
                raise FlagsmithIntegrationError("flag_list_page_limit")
            self._validate_next_url(next_url)
            payload = self._request("GET", next_url)
            if isinstance(payload, list):
                page_states = payload
                next_link = None
            elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
                page_states = payload["results"]
                next_link = payload.get("next")
            else:
                raise FlagsmithIntegrationError("flag_list_response_invalid")
            if any(not isinstance(state, dict) for state in page_states):
                raise FlagsmithIntegrationError("flag_list_response_invalid")
            states.extend(page_states)
            next_url = urljoin(next_url, next_link) if isinstance(next_link, str) else None

        return states

    def _read_environment(self) -> dict:
        environment = self._request(
            "GET",
            f"{self._api_url}/environments/{self._environment_key}/",
        )
        if not isinstance(environment, dict) or not isinstance(
            environment.get("project"), (str, int)
        ):
            raise FlagsmithIntegrationError("flagsmith_environment_response_invalid")
        return environment

    def _read_feature_names(self, environment: dict | None = None) -> dict[str, str]:
        environment = environment or self._read_environment()

        project_id = quote(str(environment["project"]), safe="")
        next_url: str | None = f"{self._api_url}/projects/{project_id}/features/"
        names_by_id: dict[str, str] = {}
        pages = 0

        while next_url is not None:
            pages += 1
            if pages > 20:
                raise FlagsmithIntegrationError("flag_list_page_limit")
            self._validate_next_url(next_url)
            payload = self._request("GET", next_url)
            if isinstance(payload, list):
                page_features = payload
                next_link = None
            elif isinstance(payload, dict) and isinstance(
                payload.get("results"), list
            ):
                page_features = payload["results"]
                next_link = payload.get("next")
            else:
                raise FlagsmithIntegrationError(
                    "flagsmith_feature_list_response_invalid"
                )

            for feature in page_features:
                if not isinstance(feature, dict):
                    raise FlagsmithIntegrationError(
                        "flagsmith_feature_list_response_invalid"
                    )
                feature_id = feature.get("id")
                name = feature.get("name")
                if not isinstance(feature_id, (str, int)) or not isinstance(
                    name, str
                ):
                    raise FlagsmithIntegrationError(
                        "flagsmith_feature_response_invalid"
                    )
                names_by_id[str(feature_id)] = name

            next_url = (
                urljoin(next_url, next_link) if isinstance(next_link, str) else None
            )

        return names_by_id

    def _request(self, method: str, url: str, **kwargs) -> object:
        self._validate_next_url(url)
        retryable_method = method.upper() in {"GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"}
        for attempt in range(3 if retryable_method else 1):
            try:
                response = httpx.request(
                    method,
                    url,
                    headers=self._headers,
                    timeout=self._timeout,
                    **kwargs,
                )
                if response.status_code == 429 or response.status_code >= 500:
                    if retryable_method and attempt < 2:
                        retry_after = response.headers.get("Retry-After", "")
                        delay = min(float(retry_after), 0.75) if retry_after.isdigit() else 0.1 * (2 ** attempt)
                        time.sleep(delay)
                        continue
                response.raise_for_status()
                if response.status_code == 204 or not response.content:
                    return {}
                return response.json()
            except httpx.TimeoutException as exc:
                if retryable_method and attempt < 2:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                raise FlagsmithIntegrationError("flagsmith_timeout") from exc
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                if status_code in {401, 403}:
                    code = "flagsmith_permission_denied"
                elif status_code == 404:
                    code = "flagsmith_resource_not_found"
                elif status_code == 429:
                    code = "flagsmith_rate_limited"
                else:
                    code = "flagsmith_request_rejected"
                raise FlagsmithIntegrationError(code, status_code=status_code) from exc
            except (httpx.RequestError, ValueError):
                if retryable_method and attempt < 2:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
                raise FlagsmithIntegrationError("flagsmith_unavailable") from None
        raise FlagsmithIntegrationError("flagsmith_unavailable")

    def _validate_next_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc.lower() != self._api_host:
            raise FlagsmithIntegrationError("flagsmith_pagination_url_invalid")

    @staticmethod
    def _feature_name(state: dict, names_by_id: dict[str, str]) -> str | None:
        feature = state.get("feature")
        if isinstance(feature, dict):
            name = feature.get("name")
            return name if isinstance(name, str) else None
        if isinstance(feature, (str, int)):
            return names_by_id.get(str(feature))
        return None

    @staticmethod
    def _is_environment_default(state: dict) -> bool:
        return state.get("identity") is None and state.get("feature_segment") is None
