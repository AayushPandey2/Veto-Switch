from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from security import allowlist
from security.allowlist import TargetNotAllowed


@pytest.mark.parametrize("url", [
    "http://example.com", "http://8.8.8.8:80", "http://169.254.169.254", "file:///etc/passwd",
    "http://user:pw@127.0.0.1:5001", "http://127.0.0.1:5001/admin", "gopher://127.0.0.1",
    "http://demo-app.evil.example", "http://0.0.0.0:5001",
])
def test_non_allowlisted_targets_are_refused(url):
    with pytest.raises(TargetNotAllowed):
        allowlist.validate_base_url(url)


def test_loopback_allowed():
    assert allowlist.validate_base_url("http://127.0.0.1:5001") == "http://127.0.0.1:5001"


def test_env_cannot_point_demo_target_at_public_host(monkeypatch):
    monkeypatch.setenv("KSX_TARGET_DEMO_URL", "http://example.com")
    with pytest.raises(TargetNotAllowed):
        allowlist.resolve_target("demo")


def test_unknown_target_id_refused():
    with pytest.raises(TargetNotAllowed):
        allowlist.resolve_target("anything-else")


@pytest.mark.parametrize("path", ["//evil.example/x", "http://evil.example/", "no-slash", "/a\\b"])
def test_paths_that_could_leave_the_host_are_refused(path):
    with pytest.raises(TargetNotAllowed):
        allowlist.get("demo", path)


def test_ephemeral_targets_must_be_loopback_and_cannot_shadow():
    with pytest.raises(TargetNotAllowed):
        allowlist.register_ephemeral("demo", "http://127.0.0.1:1")


def test_redirects_are_not_followed():
    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        allowlist.register_ephemeral("sbx-redirect", f"http://127.0.0.1:{srv.server_port}")
        r = allowlist.get("sbx-redirect", "/health")
        assert r.status == 302 and r.headers["location"] == "http://example.com/"
    finally:
        allowlist.unregister_ephemeral("sbx-redirect")
        srv.shutdown()
