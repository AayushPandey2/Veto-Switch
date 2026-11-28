"""Local-only API tests for the operator approval and release workflows."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from werkzeug.serving import make_server

from backend.app import create_app
from demo_app.app import create_app as create_demo_app
from demo_app.config import DemoSettings
from demo_app.database import get_connection


@pytest.fixture
def platform(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "demo.sqlite3"
    env = {
        "KILLSWITCH_DEMO_ENV": "local",
        "KILLSWITCH_DEMO_MODE": "true",
        "KILLSWITCH_ALLOW_VULNERABLE_ROUTES": "true",
        "KILLSWITCH_DEMO_DATABASE": str(database_path),
        "KILLSWITCH_FLAG_ADAPTER": "local",
        "KILLSWITCH_FLAG_SEARCH_V1": "true",
        "KILLSWITCH_FLAG_SEARCH_V2": "false",
        "KILLSWITCH_FLAG_FILES_V1": "true",
        "KILLSWITCH_FLAG_FILES_V2": "false",
        "KILLSWITCH_OPERATOR_PASSPHRASE": "test-operator-passphrase",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    demo = create_demo_app(
        DemoSettings(
            environment="local",
            demo_mode=True,
            allow_vulnerable_routes=True,
            database_path=database_path,
        )
    )
    server = make_server("127.0.0.1", 0, demo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    demo_url = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("KILLSWITCH_DEMO_APP_URL", demo_url)
    api = create_app(
        database_path=database_path,
        operator_passphrase="test-operator-passphrase",
        demo_app_url=demo_url,
    )
    try:
        with TestClient(api) as client:
            yield client, database_path
    finally:
        server.shutdown()
        thread.join(timeout=3)


def _headers() -> dict[str, str]:
    return {"X-Operator-Passphrase": "test-operator-passphrase"}


def _create_and_contain(client: TestClient, category: str, route: str) -> tuple[dict, dict]:
    finding = client.post(
        "/findings",
        headers=_headers(),
        json={
            "finding_id": f"test-{category}",
            "category": category,
            "affected_route": route,
            "severity": "high",
            "status": "reproduced",
            "evidence_ids": ["synthetic-evidence-01"],
            "evidence_summary": "Synthetic test finding for the local demo.",
            "reporter": "test-suite",
        },
    )
    assert finding.status_code == 201
    incident = finding.json()
    proposal = client.post(f"/incidents/{incident['id']}/analyze", headers=_headers())
    assert proposal.status_code == 200
    approval = proposal.json()
    decision = client.post(
        f"/proposals/{approval['id']}/decision",
        headers=_headers(),
        json={
            "decision": "approve",
            "actor": "test-operator",
            "proposal_hash": approval["proposal_hash"],
            "reason": "Local integration test",
        },
    )
    assert decision.status_code == 200
    applied = client.post(
        f"/proposals/{approval['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": approval["proposal_hash"]},
    )
    assert applied.status_code == 200
    assert applied.json()["readback_verified"] is True
    repeated_apply = client.post(
        f"/proposals/{approval['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": approval["proposal_hash"]},
    )
    assert repeated_apply.status_code == 200
    assert repeated_apply.json()["operation_id"] == applied.json()["operation_id"]
    verified = client.post(f"/incidents/{incident['id']}/verify", headers=_headers())
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    return incident, approval


@pytest.mark.parametrize(
    ("category", "route", "safe_flag"),
    [("sqli", "/search", "search_v2"), ("path_traversal", "/files", "files_v2")],
)
def test_containment_patch_stage_and_rollback_are_approved(
    platform,
    category: str,
    route: str,
    safe_flag: str,
) -> None:
    client, _database_path = platform
    incident, _proposal = _create_and_contain(client, category, route)
    detail = client.get(f"/incidents/{incident['id']}", headers=_headers()).json()
    assert detail["operation_receipt"]["safe_flag_unchanged"] is True
    assert detail["operation_receipt"]["after"][safe_flag] == "disabled"

    patch = client.post(f"/incidents/{incident['id']}/patch", headers=_headers())
    assert patch.status_code == 200
    patch_test = client.post(f"/incidents/{incident['id']}/patch/test", headers=_headers())
    assert patch_test.status_code == 200
    assert patch_test.json()["status"] == "passed"

    release_response = client.post(
        f"/incidents/{incident['id']}/rollout",
        headers=_headers(),
        json={"percentage": 25},
    )
    assert release_response.status_code == 200
    release = release_response.json()
    assert release["status"] == "pending_approval"
    assert release["selected_count"] == 5
    assert release["desired_overrides"]

    before_approval = client.get(f"/flags", headers=_headers()).json()["flags"][safe_flag]
    assert before_approval == "disabled"
    decision = client.post(
        f"/release-proposals/{release['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": release["proposal_hash"]},
    )
    assert decision.status_code == 200
    applied = client.post(
        f"/release-proposals/{release['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": release["proposal_hash"]},
    )
    assert applied.status_code == 200
    receipt = applied.json()
    assert receipt["readback_verified"] is True
    assert receipt["app_evaluation_verified"] is True
    assert sum(receipt["evaluation_checks"].values()) == 20

    rollback_response = client.post(
        f"/incidents/{incident['id']}/rollouts/{release['id']}/rollback",
        headers=_headers(),
    )
    assert rollback_response.status_code == 200
    rollback = rollback_response.json()
    assert rollback["action"] == "rollback"
    assert rollback["status"] == "pending_approval"
    # A rollback proposal alone cannot alter the five enabled demo identities.
    assert client.get("/flags", headers=_headers()).json()["flags"][safe_flag] == "disabled"
    rejected_or_unapproved = client.post(
        f"/release-proposals/{rollback['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": rollback["proposal_hash"]},
    )
    assert rejected_or_unapproved.status_code == 409
    assert rejected_or_unapproved.json()["detail"]["code"] == "approval_required"

    rollback_decision = client.post(
        f"/release-proposals/{rollback['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": rollback["proposal_hash"]},
    )
    assert rollback_decision.status_code == 200
    rollback_apply = client.post(
        f"/release-proposals/{rollback['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": rollback["proposal_hash"]},
    )
    assert rollback_apply.status_code == 200
    assert rollback_apply.json()["app_evaluation_verified"] is True
    assert set(rollback_apply.json()["after"].values()) == {None}

    report = client.get(f"/incidents/{incident['id']}/report", headers=_headers())
    assert report.status_code == 200
    assert len(report.json()["releases"]) == 2
    assert len(report.json()["patch_tests"]) == 1


def test_operator_auth_finding_dedup_and_unmapped_finding(platform) -> None:
    client, _database_path = platform
    unauthorized = client.get("/incidents")
    assert unauthorized.status_code == 401

    body = {
        "finding_id": "external-cve-1",
        "category": "dependency_cve",
        "affected_component": "demo-package",
        "severity": "critical",
        "status": "suspected",
        "evidence_summary": "Stored but not mapped to a demo action.",
    }
    first = client.post("/findings", headers=_headers(), json=body)
    second = client.post("/findings", headers=_headers(), json=body)
    assert first.status_code == 201
    assert second.json()["duplicate"] is True
    assert second.json()["id"] == first.json()["id"]
    assert first.json()["mapped"] is False
    analysis = client.post(f"/incidents/{first.json()['id']}/analyze", headers=_headers())
    assert analysis.status_code == 422
    assert analysis.json()["detail"]["code"] == "finding_mapping_unavailable"

    suspected = client.post(
        "/findings",
        headers=_headers(),
        json={
            "finding_id": "suspected-sqli-1",
            "category": "sqli",
            "severity": "medium",
            "status": "suspected",
            "evidence_summary": "This claim has not been reproduced yet.",
        },
    ).json()
    not_reproduced = client.post(f"/incidents/{suspected['id']}/analyze", headers=_headers())
    assert not_reproduced.status_code == 409
    assert not_reproduced.json()["detail"]["code"] == "finding_not_reproduced"


def test_incident_report_and_timeline_are_persistent_and_authenticated(platform) -> None:
    client, database_path = platform
    incident, proposal = _create_and_contain(client, "sqli", "/search")

    for path in (
        f"/incidents/{incident['id']}",
        f"/incidents/{incident['id']}/events",
        f"/incidents/{incident['id']}/report",
        "/flags/coverage",
    ):
        assert client.get(path).status_code == 401

    restarted_app = create_app(
        database_path=database_path,
        operator_passphrase="test-operator-passphrase",
        demo_app_url="http://127.0.0.1:1",
    )
    with TestClient(restarted_app) as restarted_client:
        detail = restarted_client.get(
            f"/incidents/{incident['id']}", headers=_headers()
        )
        events = restarted_client.get(
            f"/incidents/{incident['id']}/events", headers=_headers()
        )
        report = restarted_client.get(
            f"/incidents/{incident['id']}/report", headers=_headers()
        )

    assert detail.status_code == events.status_code == report.status_code == 200
    assert detail.json()["proposal"]["id"] == proposal["id"]
    assert detail.json()["operation_receipt"]["readback_verified"] is True
    event_types = {event["event_type"] for event in events.json()["events"]}
    assert {"proposal_created", "proposal_approved", "flag_change_applied"}.issubset(event_types)
    assert report.json()["incident"]["id"] == incident["id"]
    assert report.json()["operation_receipt"]["readback_verified"] is True


def test_wrong_hash_rejection_and_expiry_prevent_containment(platform) -> None:
    client, database_path = platform
    finding = client.post(
        "/findings",
        headers=_headers(),
        json={
            "finding_id": "rejected-finding",
            "category": "sqli",
            "severity": "high",
            "status": "reproduced",
            "evidence_summary": "Synthetic finding for approval enforcement.",
        },
    ).json()
    proposal = client.post(f"/incidents/{finding['id']}/analyze", headers=_headers()).json()
    wrong_hash = client.post(
        f"/proposals/{proposal['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": "0" * 64},
    )
    assert wrong_hash.status_code == 409
    assert wrong_hash.json()["detail"]["code"] == "proposal_hash_mismatch"

    reject = client.post(
        f"/proposals/{proposal['id']}/decision",
        headers=_headers(),
        json={"decision": "reject", "actor": "test-operator", "proposal_hash": proposal["proposal_hash"]},
    )
    assert reject.status_code == 200
    blocked = client.post(
        f"/proposals/{proposal['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": proposal["proposal_hash"]},
    )
    assert blocked.status_code == 409
    assert client.get("/flags", headers=_headers()).json()["flags"]["search_v1"] == "enabled"

    expired_finding = client.post(
        "/findings",
        headers=_headers(),
        json={
            "finding_id": "expired-finding",
            "category": "sqli",
            "severity": "high",
            "status": "reproduced",
            "evidence_summary": "Synthetic finding for expiry enforcement.",
        },
    ).json()
    expired = client.post(f"/incidents/{expired_finding['id']}/analyze", headers=_headers()).json()
    with get_connection(database_path) as connection:
        connection.execute(
            "UPDATE proposals SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            (expired["id"],),
        )
    expired_decision = client.post(
        f"/proposals/{expired['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": expired["proposal_hash"]},
    )
    assert expired_decision.status_code == 409
    assert expired_decision.json()["detail"]["code"] == "proposal_expired"


def test_stale_containment_approval_is_rejected(platform, monkeypatch: pytest.MonkeyPatch) -> None:
    from demo_app.database import set_demo_flag_overrides

    client, database_path = platform
    finding = client.post(
        "/findings",
        headers=_headers(),
        json={
            "finding_id": "stale-search-finding",
            "category": "sqli",
            "severity": "high",
            "status": "reproduced",
            "evidence_summary": "A state change after approval makes the snapshot stale.",
        },
    ).json()
    proposal = client.post(f"/incidents/{finding['id']}/analyze", headers=_headers()).json()
    decision = client.post(
        f"/proposals/{proposal['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": proposal["proposal_hash"]},
    )
    assert decision.status_code == 200
    set_demo_flag_overrides(database_path, {"search_v2": True}, actor="external-change")
    applied = client.post(
        f"/proposals/{proposal['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": proposal["proposal_hash"]},
    )
    assert applied.status_code == 409
    assert applied.json()["detail"]["code"] == "flag_state_changed"
    assert client.get("/flags", headers=_headers()).json()["flags"]["search_v1"] == "enabled"


def test_reset_and_telemetry_are_local_and_bounded(platform) -> None:
    client, _database_path = platform
    generated = client.post(
        "/telemetry/generate",
        headers=_headers(),
        json={"requests": 7, "route": "/search"},
    )
    assert generated.status_code == 200
    assert generated.json()["simulation"] is True
    assert generated.json()["completed"] == 7
    telemetry = client.get("/telemetry", headers=_headers()).json()
    assert telemetry["simulation"] is True
    assert sum(item["requests"] for item in telemetry["summary"]) >= 7

    reset = client.post("/demo/reset", headers=_headers())
    assert reset.status_code == 200
    assert client.get("/incidents", headers=_headers()).json()["incidents"] == []
    assert client.get("/telemetry", headers=_headers()).json()["recent"] == []
    assert set(client.get("/flags", headers=_headers()).json()["flags"].values()) == {"disabled"}


@pytest.mark.parametrize(("percentage", "expected_count"), [(5, 1), (25, 5), (50, 10), (100, 20)])
def test_rollout_stage_selects_expected_number_of_fixed_identities(
    platform,
    percentage: int,
    expected_count: int,
) -> None:
    client, _database_path = platform
    incident, _proposal = _create_and_contain(client, "sqli", "/search")
    client.post(f"/incidents/{incident['id']}/patch", headers=_headers())
    patch_test = client.post(f"/incidents/{incident['id']}/patch/test", headers=_headers())
    assert patch_test.json()["status"] == "passed"
    rollout = client.post(
        f"/incidents/{incident['id']}/rollout",
        headers=_headers(),
        json={"percentage": percentage},
    )
    assert rollout.status_code == 200
    assert rollout.json()["selected_count"] == expected_count
    assert len(rollout.json()["selected_identities"]) == expected_count


def test_expired_approved_rollout_is_closed_and_does_not_block_replacement(platform) -> None:
    client, database_path = platform
    incident, _proposal = _create_and_contain(client, "sqli", "/search")
    client.post(f"/incidents/{incident['id']}/patch", headers=_headers())
    patch_test = client.post(f"/incidents/{incident['id']}/patch/test", headers=_headers())
    assert patch_test.json()["status"] == "passed"

    expired_release = client.post(
        f"/incidents/{incident['id']}/rollout",
        headers=_headers(),
        json={"percentage": 5},
    ).json()
    approved = client.post(
        f"/release-proposals/{expired_release['id']}/decision",
        headers=_headers(),
        json={
            "decision": "approve",
            "actor": "test-operator",
            "proposal_hash": expired_release["proposal_hash"],
        },
    )
    assert approved.status_code == 200
    with get_connection(database_path) as connection:
        connection.execute(
            "UPDATE release_proposals SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", expired_release["id"]),
        )

    replacement = client.post(
        f"/incidents/{incident['id']}/rollout",
        headers=_headers(),
        json={"percentage": 5},
    )
    assert replacement.status_code == 200

    with get_connection(database_path) as connection:
        status = connection.execute(
            "SELECT status FROM release_proposals WHERE id = ?",
            (expired_release["id"],),
        ).fetchone()["status"]
        event_count = connection.execute(
            "SELECT COUNT(*) AS count FROM audit_events "
            "WHERE incident_id = ? AND event_type = 'release_proposal_expired'",
            (incident["id"],),
        ).fetchone()["count"]
    assert status == "expired"
    assert event_count == 1
    assert replacement.json()["status"] == "pending_approval"


def test_flagsmith_mode_never_allows_local_demo_reset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KILLSWITCH_DEMO_ENV", "local")
    monkeypatch.setenv("KILLSWITCH_DEMO_MODE", "false")
    monkeypatch.setenv("KILLSWITCH_ALLOW_VULNERABLE_ROUTES", "false")
    monkeypatch.setenv("KILLSWITCH_DEMO_DATABASE", str(tmp_path / "flagsmith.sqlite3"))
    monkeypatch.setenv("KILLSWITCH_FLAG_ADAPTER", "flagsmith")
    monkeypatch.setenv("KILLSWITCH_PLATFORM_FLAGSMITH_ENVIRONMENT_KEY", "fake-environment")
    monkeypatch.setenv("KILLSWITCH_PLATFORM_FLAGSMITH_SERVER_ENVIRONMENT_KEY", "fake-sdk-key")
    monkeypatch.setenv("KILLSWITCH_PLATFORM_FLAGSMITH_MANAGEMENT_TOKEN", "fake-management-token")
    app = create_app(database_path=tmp_path / "flagsmith.sqlite3", operator_passphrase="test-operator-passphrase")
    with TestClient(app) as client:
        response = client.post("/demo/reset", headers=_headers())
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "reset_local_adapter_only"


def test_failed_rollout_guardrail_shows_and_allows_separately_approved_rollback(
    platform,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, database_path = platform
    incident, _proposal = _create_and_contain(client, "sqli", "/search")
    client.post(f"/incidents/{incident['id']}/patch", headers=_headers())
    patch_test = client.post(f"/incidents/{incident['id']}/patch/test", headers=_headers())
    assert patch_test.json()["status"] == "passed"
    release = client.post(
        f"/incidents/{incident['id']}/rollout",
        headers=_headers(),
        json={"percentage": 5},
    ).json()
    approved = client.post(
        f"/release-proposals/{release['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": release["proposal_hash"]},
    )
    assert approved.status_code == 200

    class WrongEvaluation:
        status_code = 200

        @staticmethod
        def json() -> dict[str, str]:
            return {
                "variant": "safe_fallback",
                "flag_states": {"search_v1": "disabled", "search_v2": "disabled"},
            }

    with monkeypatch.context() as patcher:
        patcher.setattr("backend.app.httpx.get", lambda *_args, **_kwargs: WrongEvaluation())
        failed_apply = client.post(
            f"/release-proposals/{release['id']}/apply",
            headers=_headers(),
            json={"proposal_hash": release["proposal_hash"]},
        )

    assert failed_apply.status_code == 502
    receipt = failed_apply.json()["detail"]["receipt"]
    assert receipt["guardrail_status"] == "violated"
    assert receipt["recommendation"] == "rollback_proposed"
    assert len(receipt["guardrail_violations"]) == 1

    rollback = client.post(
        f"/incidents/{incident['id']}/rollouts/{release['id']}/rollback",
        headers=_headers(),
    )
    assert rollback.status_code == 200
    expired_rollback = rollback.json()
    with get_connection(database_path) as connection:
        connection.execute(
            "UPDATE release_proposals SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", expired_rollback["id"]),
        )

    refreshed_rollback = client.post(
        f"/incidents/{incident['id']}/rollouts/{release['id']}/rollback",
        headers=_headers(),
    )
    assert refreshed_rollback.status_code == 200
    with get_connection(database_path) as connection:
        expired_status = connection.execute(
            "SELECT status FROM release_proposals WHERE id = ?",
            (expired_rollback["id"],),
        ).fetchone()["status"]
    assert expired_status == "expired"

    rollback_proposal = refreshed_rollback.json()
    assert rollback_proposal["status"] == "pending_approval"
    decision = client.post(
        f"/release-proposals/{rollback_proposal['id']}/decision",
        headers=_headers(),
        json={
            "decision": "approve",
            "actor": "test-operator",
            "proposal_hash": rollback_proposal["proposal_hash"],
        },
    )
    assert decision.status_code == 200
    restored = client.post(
        f"/release-proposals/{rollback_proposal['id']}/apply",
        headers=_headers(),
        json={"proposal_hash": rollback_proposal["proposal_hash"]},
    )
    assert restored.status_code == 200
    assert restored.json()["app_evaluation_verified"] is True


def test_unknown_demo_flag_evaluation_is_not_reported_as_guardrail_violation(
    platform,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _database_path = platform
    incident, _proposal = _create_and_contain(client, "sqli", "/search")
    client.post(f"/incidents/{incident['id']}/patch", headers=_headers())
    patch_test = client.post(f"/incidents/{incident['id']}/patch/test", headers=_headers())
    assert patch_test.json()["status"] == "passed"
    release = client.post(
        f"/incidents/{incident['id']}/rollout",
        headers=_headers(),
        json={"percentage": 5},
    ).json()
    approved = client.post(
        f"/release-proposals/{release['id']}/decision",
        headers=_headers(),
        json={"decision": "approve", "actor": "test-operator", "proposal_hash": release["proposal_hash"]},
    )
    assert approved.status_code == 200

    class UnknownEvaluation:
        status_code = 200

        @staticmethod
        def json() -> dict[str, str | dict[str, str]]:
            return {
                "variant": "safe_fallback",
                "flag_states": {"search_v1": "disabled", "search_v2": "unknown"},
            }

    with monkeypatch.context() as patcher:
        patcher.setattr("backend.app.httpx.get", lambda *_args, **_kwargs: UnknownEvaluation())
        failed_apply = client.post(
            f"/release-proposals/{release['id']}/apply",
            headers=_headers(),
            json={"proposal_hash": release["proposal_hash"]},
        )

    assert failed_apply.status_code == 503
    receipt = failed_apply.json()["detail"]["receipt"]
    assert receipt["guardrail_status"] == "unknown"
    assert receipt["guardrail_violations"] == []
    assert receipt["app_evaluation_unknown"] is True
    assert receipt["recommendation"] == "retry_verification"
