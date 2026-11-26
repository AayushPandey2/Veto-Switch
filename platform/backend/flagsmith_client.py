"""Server-only Flagsmith Management API adapter for approved flag changes."""

from __future__ import annotations

from urllib.parse import quote, urljoin, urlparse

import httpx


class FlagsmithIntegrationError(RuntimeError):
    """A safe-to-report Flagsmith failure without request or credential data."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


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
        states = self._read_environment_states()
        result: dict[str, bool] = {}
        for name in names:
            matches = [state for state in states if self._feature_name(state) == name]
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
        states = self._read_environment_states()
        matches = [state for state in states if self._feature_name(state) == name]
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

        url = (
            f"{self._api_url}/environments/{self._environment_key}"
            f"/featurestates/{quote(str(feature_state_id), safe='')}/"
        )
        self._request("PATCH", url, json={"enabled": enabled})
        readback = self.read_flags((name,))[name]
        if readback is not enabled:
            raise FlagsmithIntegrationError("flag_readback_failed")
        return readback

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

    def _request(self, method: str, url: str, **kwargs) -> object:
        self._validate_next_url(url)
        try:
            response = httpx.request(
                method,
                url,
                headers=self._headers,
                timeout=self._timeout,
                **kwargs,
            )
            response.raise_for_status()
            if response.status_code == 204 or not response.content:
                return {}
            return response.json()
        except httpx.TimeoutException as exc:
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
            raise FlagsmithIntegrationError(code) from exc
        except (httpx.RequestError, ValueError):
            raise FlagsmithIntegrationError("flagsmith_unavailable") from None

    def _validate_next_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc.lower() != self._api_host:
            raise FlagsmithIntegrationError("flagsmith_pagination_url_invalid")

    @staticmethod
    def _feature_name(state: dict) -> str | None:
        feature = state.get("feature")
        if isinstance(feature, dict):
            name = feature.get("name")
            return name if isinstance(name, str) else None
        return None

    @staticmethod
    def _is_environment_default(state: dict) -> bool:
        return state.get("identity") is None and state.get("feature_segment") is None
