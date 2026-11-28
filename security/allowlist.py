"""Authorization boundary: which targets security tests may touch, and the only
HTTP client the tests are allowed to use.

There is no "scan this URL" entry point. Tests address targets by ID; IDs map to
base URLs whose host must be loopback or a known compose service name, and whose
resolved addresses must be loopback/private. Redirects are never followed, so a
target cannot bounce a probe to another host.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "demo-app", "patch-target"}
MAX_BODY_BYTES = 256 * 1024
DEFAULT_TIMEOUT_S = 5.0

STATIC_TARGETS = {
    "demo": {"env": "KSX_TARGET_DEMO_URL", "default": "http://127.0.0.1:5001",
             "role": "vulnerable demo instance"},
    "patch": {"env": "KSX_TARGET_PATCH_URL", "default": "http://127.0.0.1:5002",
              "role": "candidate-patch test instance"},
}

_ephemeral: dict[str, str] = {}
_lock = threading.Lock()


class TargetNotAllowed(ValueError):
    pass


def _host_ok(host: str) -> bool:
    if host not in ALLOWED_HOSTS:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        if not (ip.is_loopback or ip.is_private):
            return False
    return True


def validate_base_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise TargetNotAllowed(f"scheme {parts.scheme!r} not allowed")
    if parts.username or parts.password:
        raise TargetNotAllowed("credentials in target URL are not allowed")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise TargetNotAllowed("target base URL must not carry a path, query or fragment")
    host = parts.hostname or ""
    if not _host_ok(host):
        raise TargetNotAllowed(f"host {host!r} is not an allowlisted local test host")
    return f"{parts.scheme}://{parts.netloc}"


def register_ephemeral(target_id: str, base_url: str) -> None:
    """Register a sandbox-launched target (loopback only) for the duration of a run."""
    base = validate_base_url(base_url)
    if urllib.parse.urlsplit(base).hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise TargetNotAllowed("ephemeral targets must be loopback")
    if target_id in STATIC_TARGETS:
        raise TargetNotAllowed("cannot shadow a static target")
    with _lock:
        _ephemeral[target_id] = base


def unregister_ephemeral(target_id: str) -> None:
    with _lock:
        _ephemeral.pop(target_id, None)


def resolve_target(target_id: str) -> str:
    with _lock:
        if target_id in _ephemeral:
            return _ephemeral[target_id]
    spec = STATIC_TARGETS.get(target_id)
    if spec is None:
        raise TargetNotAllowed(f"unknown target_id {target_id!r}")
    return validate_base_url(os.environ.get(spec["env"], spec["default"]))


def list_targets() -> dict:
    out = {}
    for tid, spec in STATIC_TARGETS.items():
        try:
            out[tid] = {"role": spec["role"], "base_url": resolve_target(tid), "allowed": True}
        except TargetNotAllowed as e:
            out[tid] = {"role": spec["role"], "allowed": False, "reason": str(e)}
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface the 3xx instead of following it


_opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


@dataclass
class Response:
    url_path: str
    status: int                     # 0 = no response (network error / timeout)
    body: str = ""
    headers: dict = field(default_factory=dict)
    elapsed_s: float = 0.0
    error: str | None = None

    @property
    def variant(self) -> str | None:
        return self.headers.get("x-ksx-variant")

    def json(self) -> dict | None:
        import json
        try:
            return json.loads(self.body)
        except ValueError:
            return None


def get(target_id: str, path: str, params: dict | None = None, *,
        timeout: float = DEFAULT_TIMEOUT_S, headers: dict | None = None) -> Response:
    """GET an allowlisted target. Never raises for HTTP/network errors."""
    if not path.startswith("/") or path.startswith("//") or "://" in path or "\\" in path:
        raise TargetNotAllowed(f"path {path!r} is not a plain absolute path")
    base = resolve_target(target_id)
    url = base + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    if urllib.parse.urlsplit(url).netloc != urllib.parse.urlsplit(base).netloc:
        raise TargetNotAllowed("request would leave the target host")
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    start = time.monotonic()
    try:
        with _opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_BODY_BYTES).decode("utf-8", "replace")
            return Response(path, resp.status, body, {k.lower(): v for k, v in resp.headers.items()},
                            time.monotonic() - start)
    except urllib.error.HTTPError as e:
        body = e.read(MAX_BODY_BYTES).decode("utf-8", "replace") if e.fp else ""
        return Response(path, e.code, body, {k.lower(): v for k, v in (e.headers or {}).items()},
                        time.monotonic() - start)
    except Exception as e:  # noqa: BLE001 - a failed probe is a non-result, never a crash
        return Response(path, 0, "", {}, time.monotonic() - start, error=f"{type(e).__name__}: {e}")
