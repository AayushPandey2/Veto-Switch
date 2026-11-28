from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security import sandbox
from security.service import app

PATCH = (Path(__file__).resolve().parents[1] / "fixtures" / "patches" / "sqli_fix.diff").read_text()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("KSX_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    return TestClient(app)


def _body(pid="p-svc"):
    return {"patch_id": pid, "incident_id": "inc-svc", "diff": PATCH, "base_revision": sandbox.base_revision()}


def test_patch_endpoints_fail_closed_without_configured_token(client, monkeypatch):
    monkeypatch.delenv("KSX_SECURITY_SERVICE_TOKEN", raising=False)
    assert client.post("/patches", json=_body()).status_code == 503
    monkeypatch.setenv("KSX_SECURITY_SERVICE_TOKEN", "change-me")  # the placeholder never works
    assert client.post("/patches", json=_body(), headers={"X-KSX-Token": "change-me"}).status_code == 503


def test_patch_endpoints_require_matching_token(client, monkeypatch):
    monkeypatch.setenv("KSX_SECURITY_SERVICE_TOKEN", "s3cret-test-token")
    assert client.post("/patches", json=_body(), headers={"X-KSX-Token": "wrong"}).status_code == 401
    r = client.post("/patches", json=_body(), headers={"X-KSX-Token": "s3cret-test-token"})
    assert r.status_code == 200 and "diff" not in r.json()


def test_verify_refuses_non_allowlisted_target(client):
    r = client.post("/verify", json={"incident_id": "inc-s", "test_id": "sqli_search",
                                     "target_id": "prod", "phase": "before"})
    assert r.status_code == 403


def test_verify_returns_result_and_events(client, target):
    r = client.post("/verify", json={"incident_id": "inc-s", "test_id": "sqli_search",
                                     "target_id": target.target_id, "phase": "before"})
    body = r.json()
    # Spec-default oracle (prefix match) works against an externally seeded target too.
    assert body["result"]["outcome"] == "exploit_reproduced"
    assert body["events"][0]["event_type"] == "verification_pass"


def test_registry_and_targets(client):
    assert "sqli_search" in client.get("/registry").json()["security_tests"]
    assert client.get("/targets").json()["demo"]["allowed"] is True
