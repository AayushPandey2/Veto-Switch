"""Flagsmith transport tests; all responses are mocked and no account is contacted."""

from __future__ import annotations

import threading
import time

import httpx
import pytest

from backend.flagsmith_client import FlagsmithIntegrationError, FlagsmithManagementClient


def _client() -> FlagsmithManagementClient:
    return FlagsmithManagementClient(
        environment_key="fake-environment-key",
        management_token="fake-management-token",
        api_url="https://flagsmith.test/api/v1",
    )


def test_management_api_retries_transient_get_and_limits_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = []

    def request(method: str, url: str, **kwargs):
        attempts.append(method)
        return httpx.Response(503, json={"detail": "temporary"}, request=httpx.Request(method, url))

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)
    monkeypatch.setattr("backend.flagsmith_client.time.sleep", lambda _delay: None)
    with pytest.raises(FlagsmithIntegrationError) as error:
        _client()._request("GET", "https://flagsmith.test/api/v1/projects/1/")

    assert error.value.code == "flagsmith_request_rejected"
    assert error.value.status_code == 503
    assert attempts == ["GET", "GET", "GET"]
    assert "fake-management-token" not in str(error.value)


def test_management_api_does_not_retry_identity_creation_post(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = []

    def request(method: str, url: str, **kwargs):
        attempts.append(method)
        raise httpx.ConnectError("offline", request=httpx.Request(method, url))

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)
    with pytest.raises(FlagsmithIntegrationError) as error:
        _client()._request(
            "POST",
            "https://flagsmith.test/api/v1/environments/fake/identities/",
            json={"identifier": "demo_user_01"},
        )

    assert error.value.code == "flagsmith_unavailable"
    assert attempts == ["POST"]


def test_identity_override_reads_use_bounded_parallel_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    identities = tuple(f"demo_user_{index:02d}" for index in range(1, 10))
    active = 0
    peak_active = 0
    lock = threading.Lock()

    def read_state(identity_id, _feature_id, _feature_names):
        nonlocal active, peak_active
        with lock:
            active += 1
            peak_active = max(peak_active, active)
        time.sleep(0.03)
        with lock:
            active -= 1
        return {"id": identity_id, "enabled": identity_id % 2 == 0}

    monkeypatch.setattr(client, "_read_feature_names", lambda: {"5": "search_v2"})
    monkeypatch.setattr(client, "_uses_v2_feature_versioning", lambda: False)
    monkeypatch.setattr(
        client,
        "_identities_by_identifier",
        lambda: {identity: index for index, identity in enumerate(identities, 1)},
    )
    monkeypatch.setattr(client, "_identity_feature_state", read_state)

    result = client.read_identity_feature_overrides(identities, "search_v2")

    assert result == {
        identity: index % 2 == 0
        for index, identity in enumerate(identities, 1)
    }
    assert 1 < peak_active <= 4


def test_identity_override_is_created_and_read_back(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = []
    created_identity = False
    created_override = False

    def request(method: str, url: str, **kwargs):
        nonlocal created_identity, created_override
        requests.append((method, url, kwargs.get("json")))
        req = httpx.Request(method, url)
        if url.endswith("/environments/fake-environment-key/"):
            return httpx.Response(200, json={"project": 12}, request=req)
        if url.endswith("/projects/12/features/"):
            return httpx.Response(200, json=[{"id": 5, "name": "search_v2"}], request=req)
        if url.endswith("/environments/fake-environment-key/identities/") and method == "GET":
            identities = [{"id": 44, "identifier": "demo_user_01"}] if created_identity else []
            return httpx.Response(200, json=identities, request=req)
        if url.endswith("/environments/fake-environment-key/identities/") and method == "POST":
            created_identity = True
            return httpx.Response(201, json={"id": 44, "identifier": "demo_user_01"}, request=req)
        if url.endswith("/identities/44/featurestates/") and method == "GET":
            states = [{"id": 99, "feature": 5, "enabled": True}] if created_override else []
            return httpx.Response(200, json=states, request=req)
        if url.endswith("/identities/44/featurestates/") and method == "POST":
            created_override = True
            assert kwargs["json"] == {"feature": 5, "enabled": True}
            return httpx.Response(201, json={"id": 99, "feature": 5, "enabled": True}, request=req)
        raise AssertionError(f"Unexpected mocked request: {method} {url}")

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)
    client = _client()
    result = client.apply_identity_feature_overrides({"demo_user_01": True}, "search_v2")

    assert result == {"demo_user_01": True}
    assert any(method == "POST" and url.endswith("/identities/") for method, url, _ in requests)
    assert any(method == "POST" and url.endswith("/featurestates/") for method, url, _ in requests)


def test_identity_override_delete_accepts_404_when_readback_confirms_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = []
    state_exists = True

    def request(method: str, url: str, **kwargs):
        nonlocal state_exists
        requests.append((method, url))
        req = httpx.Request(method, url)
        if url.endswith("/environments/fake-environment-key/"):
            return httpx.Response(200, json={"project": 12}, request=req)
        if url.endswith("/projects/12/features/"):
            return httpx.Response(200, json=[{"id": 5, "name": "search_v2"}], request=req)
        if url.endswith("/environments/fake-environment-key/identities/"):
            return httpx.Response(
                200,
                json=[{"id": 44, "identifier": "demo_user_01"}],
                request=req,
            )
        if url.endswith("/identities/44/featurestates/") and method == "GET":
            states = [{"id": 99, "feature": 5, "enabled": True}] if state_exists else []
            return httpx.Response(200, json=states, request=req)
        if url.endswith("/identities/44/featurestates/99/") and method == "DELETE":
            state_exists = False
            return httpx.Response(404, json={"detail": "already removed"}, request=req)
        raise AssertionError(f"Unexpected mocked request: {method} {url}")

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)

    result = _client().apply_identity_feature_overrides(
        {"demo_user_01": None},
        "search_v2",
    )

    assert result == {"demo_user_01": None}
    assert any(method == "DELETE" for method, _ in requests)


def test_versioned_identity_overrides_use_live_edge_identity_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = []
    state_exists = False
    state_enabled = False

    def request(method: str, url: str, **kwargs):
        nonlocal state_exists, state_enabled
        requests.append((method, url, kwargs.get("json")))
        req = httpx.Request(method, url)
        if url.endswith("/environments/fake-environment-key/"):
            return httpx.Response(
                200,
                json={"id": 123, "project": 12, "use_v2_feature_versioning": True},
                request=req,
            )
        if url.endswith("/projects/12/features/"):
            return httpx.Response(200, json=[{"id": 5, "name": "search_v2"}], request=req)
        if url.endswith("/edge-identities/?page_size=100"):
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"identity_uuid": "identity-uuid", "identifier": "demo_user_01"}
                    ],
                    "last_evaluated_key": None,
                },
                request=req,
            )
        if url.endswith("/edge-featurestates/") and method == "GET":
            states = (
                [
                    {
                        "featurestate_uuid": "featurestate-uuid",
                        "feature": 5,
                        "enabled": state_enabled,
                    }
                ]
                if state_exists
                else []
            )
            return httpx.Response(200, json=states, request=req)
        if url.endswith("/edge-featurestates/") and method == "POST":
            assert kwargs["json"] == {"feature": 5, "enabled": True}
            state_exists = True
            state_enabled = True
            return httpx.Response(
                201,
                json={
                    "featurestate_uuid": "featurestate-uuid",
                    "feature": 5,
                    "enabled": True,
                },
                request=req,
            )
        if url.endswith("/edge-featurestates/featurestate-uuid/") and method == "DELETE":
            state_exists = False
            return httpx.Response(204, request=req)
        raise AssertionError(f"Unexpected mocked request: {method} {url}")

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)
    client = _client()

    assert client.read_identity_feature_overrides(("demo_user_01",), "search_v2") == {
        "demo_user_01": None
    }
    assert client.apply_identity_feature_overrides(
        {"demo_user_01": True}, "search_v2"
    ) == {"demo_user_01": True}
    assert client.apply_identity_feature_overrides(
        {"demo_user_01": None}, "search_v2"
    ) == {"demo_user_01": None}

    assert any(method == "POST" and "/edge-featurestates/" in url for method, url, _ in requests)
    assert any(method == "DELETE" and "/edge-featurestates/featurestate-uuid/" in url for method, url, _ in requests)
    assert not any("/identities/44/featurestates/" in url for _, url, _ in requests)


def test_identity_override_delete_keeps_404_failure_when_state_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = []

    def request(method: str, url: str, **kwargs):
        requests.append((method, url))
        req = httpx.Request(method, url)
        if url.endswith("/environments/fake-environment-key/"):
            return httpx.Response(200, json={"project": 12}, request=req)
        if url.endswith("/projects/12/features/"):
            return httpx.Response(200, json=[{"id": 5, "name": "search_v2"}], request=req)
        if url.endswith("/environments/fake-environment-key/identities/"):
            return httpx.Response(
                200,
                json=[{"id": 44, "identifier": "demo_user_01"}],
                request=req,
            )
        if url.endswith("/identities/44/featurestates/") and method == "GET":
            return httpx.Response(
                200,
                json=[{"id": 99, "feature": 5, "enabled": True}],
                request=req,
            )
        if url.endswith("/identities/44/featurestates/99/") and method == "DELETE":
            return httpx.Response(404, json={"detail": "not found"}, request=req)
        raise AssertionError(f"Unexpected mocked request: {method} {url}")

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)

    with pytest.raises(FlagsmithIntegrationError) as error:
        _client().apply_identity_feature_overrides({"demo_user_01": None}, "search_v2")

    assert error.value.code == "flagsmith_resource_not_found"
    assert error.value.status_code == 404
    assert [method for method, _ in requests].count("DELETE") == 1


def test_versioned_environment_publishes_a_new_version_and_reads_it_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = []
    enabled = True
    value = {
        "type": "string",
        "string_value": "control",
        "integer_value": None,
        "boolean_value": None,
    }

    def request(method: str, url: str, **kwargs):
        nonlocal enabled
        requests.append((method, url, kwargs.get("json")))
        req = httpx.Request(method, url)
        if url.endswith("/environments/fake-environment-key/"):
            return httpx.Response(
                200,
                json={"id": 123, "project": 12, "use_v2_feature_versioning": True},
                request=req,
            )
        if url.endswith("/projects/12/features/"):
            return httpx.Response(200, json=[{"id": 5, "name": "search_v1"}], request=req)
        if url.endswith("/environments/fake-environment-key/featurestates/"):
            states = [
                {
                    "id": 99,
                    "feature": 5,
                    "enabled": enabled,
                    "identity": None,
                    "feature_segment": None,
                    "environment_feature_version": "current-version",
                }
            ]
            return httpx.Response(200, json=states, request=req)
        if url.endswith(
            "/environments/123/features/5/versions/current-version/featurestates/"
        ):
            states = [
                {
                    "id": 99,
                    "feature": 5,
                    "enabled": enabled,
                    "identity": None,
                    "feature_segment": None,
                    "environment_feature_version": "current-version",
                    "feature_state_value": value,
                    "multivariate_feature_state_values": [
                        {
                            "id": 8,
                            "multivariate_feature_option": 22,
                            "percentage_allocation": 100,
                        }
                    ],
                }
            ]
            return httpx.Response(200, json=states, request=req)
        if url.endswith("/environments/123/features/5/versions/") and method == "POST":
            body = kwargs["json"]
            state_update = body["feature_states_to_update"][0]
            assert body["publish_immediately"] is True
            assert state_update["enabled"] is False
            assert state_update["feature_state_value"] == value
            assert state_update["multivariate_feature_state_values"] == [
                {
                    "multivariate_feature_option": 22,
                    "percentage_allocation": 100,
                }
            ]
            assert "id" not in state_update["multivariate_feature_state_values"][0]
            enabled = False
            return httpx.Response(
                201,
                json={"uuid": "new-version", "published": True, "is_live": True},
                request=req,
            )
        raise AssertionError(f"Unexpected mocked request: {method} {url}")

    monkeypatch.setattr("backend.flagsmith_client.httpx.request", request)

    assert _client().set_flag_enabled("search_v1", False) is False
    assert any(
        method == "POST" and url.endswith("/environments/123/features/5/versions/")
        for method, url, _body in requests
    )
    assert not any(method == "PATCH" for method, _url, _body in requests)
