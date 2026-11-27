"""Offline tests for the isolated local Flask demonstration app."""

import sqlite3
from pathlib import Path

import pytest
from demo_app.app import create_app
from demo_app.config import DemoSettings
from demo_app.database import (
    get_connection,
    get_demo_telemetry,
    set_demo_identity_flag_overrides,
)
from demo_app.feature_flags import FeatureFlagProvider, FeatureState


def _settings(
    database_path: Path,
    *,
    demo_mode: bool = False,
    allow_vulnerable_routes: bool = False,
) -> DemoSettings:
    return DemoSettings(
        environment="test",
        demo_mode=demo_mode,
        allow_vulnerable_routes=allow_vulnerable_routes,
        database_path=database_path,
    )


def test_demo_settings_reject_unsafe_direct_construction(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Only local and test environments"):
        DemoSettings("production", False, False, tmp_path / "demo.sqlite3")

    with pytest.raises(ValueError, match="require explicit demo mode"):
        DemoSettings("local", False, True, tmp_path / "demo.sqlite3")


def test_sqlite_connection_closes_when_context_exits(tmp_path: Path) -> None:
    with get_connection(tmp_path / "demo.sqlite3") as connection:
        connection.execute("CREATE TABLE connection_check (id INTEGER PRIMARY KEY)")

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_safe_search_returns_matching_synthetic_document(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "demo.sqlite3"))

    response = app.test_client().get("/search?q=demo_user_01")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["variant"] == "safe_fallback"
    assert payload["count"] == 1
    assert payload["results"][0]["username"] == "demo_user_01"


@pytest.mark.parametrize(
    ("route", "expected_flags"),
    [
        ("/search", {"search_v1", "search_v2"}),
        ("/files", {"files_v1", "files_v2"}),
    ],
)
def test_route_batches_flag_evaluation_and_reports_states(
    tmp_path: Path,
    route: str,
    expected_flags: set[str],
) -> None:
    app = create_app(
        _settings(
            tmp_path / "demo.sqlite3",
            demo_mode=True,
            allow_vulnerable_routes=True,
        )
    )
    provider: FeatureFlagProvider = app.extensions["feature_flags"]

    class FakeFlags:
        @staticmethod
        def is_feature_enabled(name: str) -> bool:
            return False

    class FakeFlagsmith:
        calls = 0

        def get_identity_flags(self, _identity: str):
            self.calls += 1
            return FakeFlags()

    fake_flagsmith = FakeFlagsmith()
    provider._adapter = "flagsmith"
    provider._flagsmith = fake_flagsmith

    query = {"q": "demo_user_01"} if route == "/search" else {"path": "readme.txt"}
    query["identity"] = "demo_user_01"
    response = app.test_client().get(route, query_string=query)

    assert response.status_code == 200
    assert response.get_json()["flag_states"] == {
        name: "disabled" for name in expected_flags
    }
    assert fake_flagsmith.calls == 1


def test_flag_evaluation_failure_is_unknown_and_fails_closed(tmp_path: Path) -> None:
    app = create_app(
        _settings(
            tmp_path / "demo.sqlite3",
            demo_mode=True,
            allow_vulnerable_routes=True,
        )
    )
    provider: FeatureFlagProvider = app.extensions["feature_flags"]

    class BrokenFlagsmith:
        def get_identity_flags(self, _identity: str):
            raise TimeoutError("Flagsmith did not respond")

    provider._adapter = "flagsmith"
    provider._flagsmith = BrokenFlagsmith()

    response = app.test_client().get(
        "/search?q=demo_user_01&identity=demo_user_01"
    )

    assert response.status_code == 200
    assert response.get_json()["variant"] == "safe_fallback"
    assert response.get_json()["flag_states"] == {
        "search_v1": "unknown",
        "search_v2": "unknown",
    }


def test_search_rejects_missing_and_oversized_queries(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "demo.sqlite3"))
    client = app.test_client()

    missing = client.get("/search")
    oversized = client.get("/search", query_string={"q": "x" * 101})

    assert missing.status_code == 400
    assert oversized.status_code == 400


def test_vulnerable_demo_is_hidden_by_default(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "demo.sqlite3"))

    response = app.test_client().get("/demo/search-v1?q=demo_user_01")

    assert response.status_code == 404


def test_vulnerable_demo_requires_both_demo_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KILLSWITCH_FLAG_SEARCH_V1", "true")

    app = create_app(
        _settings(
            tmp_path / "demo.sqlite3",
            demo_mode=True,
            allow_vulnerable_routes=False,
        )
    )

    response = app.test_client().get("/demo/search-v1?q=demo_user_01")

    assert response.status_code == 404


def test_search_uses_safe_fallback_when_vulnerable_flag_is_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KILLSWITCH_FLAG_SEARCH_V1", "false")
    app = create_app(
        _settings(
            tmp_path / "demo.sqlite3",
            demo_mode=True,
            allow_vulnerable_routes=True,
        )
    )
    client = app.test_client()

    response = client.get("/search", query_string={"q": "' OR 1=1 -- "})
    status = client.get("/status")

    assert response.status_code == 200
    assert response.get_json()["variant"] == "safe_fallback"
    assert response.get_json()["count"] == 0
    assert status.status_code == 200
    assert status.get_json()["status"] == "operational"


def test_enabled_demo_exposes_injection_only_in_synthetic_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KILLSWITCH_FLAG_SEARCH_V1", "true")
    app = create_app(
        _settings(
            tmp_path / "demo.sqlite3",
            demo_mode=True,
            allow_vulnerable_routes=True,
        )
    )
    client = app.test_client()

    routed = client.get("/search", query_string={"q": "' OR 1=1 -- "})
    injected = client.get("/demo/search-v1", query_string={"q": "' OR 1=1 -- "})

    assert routed.status_code == 200
    assert routed.get_json()["variant"] == "search_v1"
    assert routed.get_json()["count"] == 20
    assert injected.status_code == 200
    assert injected.get_json()["warning"].startswith("Intentionally vulnerable")
    assert injected.get_json()["count"] == 20


def test_enabled_search_v2_takes_precedence_over_search_v1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KILLSWITCH_FLAG_SEARCH_V1", "true")
    monkeypatch.setenv("KILLSWITCH_FLAG_SEARCH_V2", "true")
    app = create_app(
        _settings(
            tmp_path / "demo.sqlite3",
            demo_mode=True,
            allow_vulnerable_routes=True,
        )
    )

    response = app.test_client().get(
        "/search",
        query_string={"q": "' OR 1=1 -- "},
    )

    assert response.status_code == 200
    assert response.get_json()["variant"] == "search_v2"
    assert response.get_json()["count"] == 0


def test_identity_override_selects_only_the_named_synthetic_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KILLSWITCH_FLAG_SEARCH_V1", "true")
    settings = _settings(
        tmp_path / "demo.sqlite3",
        demo_mode=True,
        allow_vulnerable_routes=True,
    )
    app = create_app(settings)
    set_demo_identity_flag_overrides(
        settings.database_path,
        {("demo_user_01", "search_v1"): False},
        actor="test-operator",
    )
    client = app.test_client()

    contained = client.get(
        "/search",
        query_string={"q": "demo_user_01", "identity": "demo_user_01"},
    )
    unaffected = client.get(
        "/search",
        query_string={"q": "demo_user_02", "identity": "demo_user_02"},
    )
    direct_unsafe = client.get(
        "/demo/search-v1",
        query_string={"q": "demo_user_01", "identity": "demo_user_01"},
    )

    assert contained.status_code == 200
    assert contained.get_json()["variant"] == "safe_fallback"
    assert unaffected.get_json()["variant"] == "search_v1"
    assert direct_unsafe.status_code == 404


def test_invalid_demo_identity_is_rejected_and_telemetry_omits_query_data(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "demo.sqlite3")
    app = create_app(settings)
    client = app.test_client()

    invalid = client.get(
        "/search",
        query_string={"q": "private-search-term", "identity": "someone-else"},
    )
    safe = client.get(
        "/search",
        query_string={"q": "demo_user_01", "identity": "demo_user_01"},
    )
    telemetry = get_demo_telemetry(settings.database_path)

    assert invalid.status_code == 400
    assert safe.status_code == 200
    assert telemetry["simulation"] is True
    assert "private-search-term" not in str(telemetry)
    assert telemetry["recent"][0]["identity"] == "demo_user_01"
