"""Sandbox runner: launch an owned target (original or patched) and test it.

Two launch modes:
  docker : default. Read-only code mount, read-only root FS, all capabilities
           dropped, no-new-privileges, non-root user, CPU/memory/pid limits,
           port published on 127.0.0.1 only. No Docker socket is mounted.
  local  : dev fallback for machines without Docker. Runs the target as a host
           subprocess bound to 127.0.0.1 with a scrubbed environment. This is
           NOT isolation, so it is refused unless KSX_ALLOW_LOCAL_SANDBOX=1.

Patched code is staged in an ephemeral directory; the original source is never
modified. Results are trusted only when the revision the caller requested, the
revision we computed and the revision the running app reports all agree.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from security import allowlist, patching, probes, registry
from security.evidence import ArtifactStore, safe_id, utc_now
from security.exploit_verifier import run_phase
from security.models import CheckResult, TestRunRequest
from security.probes import OracleContext
from security.redact import redact_text
from security.revision import sha256_text, tree_revision, tracked
from security import seed

HERE = Path(__file__).resolve().parent

# Source trees the sandbox may launch, and the only files a patch may touch.
SOURCES = {
    "stand_in": {"source_dir": HERE / "stand_in_app", "allowed_files": {"app.py"}, "entry": "app.py",
                 "container_port": 5001, "image": "ksx-sandbox:latest", "dockerfile_dir": HERE / "stand_in_app"},
}
DEFAULT_SOURCE = os.environ.get("KSX_PATCH_SOURCE", "stand_in")
SANDBOX_TIMEOUT_S = 90
HEALTH_TIMEOUT_S = 25

DOCKER_LIMITS = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                 "--tmpfs", "/tmp:rw,size=16m", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
                 "--user", "10001"]


class SandboxUnavailable(RuntimeError):
    pass


# -- environment detection -------------------------------------------------------

def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, timeout=15).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def local_allowed() -> bool:
    return os.environ.get("KSX_ALLOW_LOCAL_SANDBOX") == "1"


def choose_mode(mode: str = "auto") -> str:
    if mode in {"docker", "auto"} and docker_available():
        return "docker"
    if mode in {"local", "auto"} and local_allowed():
        return "local"
    if mode == "docker":
        raise SandboxUnavailable("Docker is not available")
    raise SandboxUnavailable("no sandbox available: start Docker, or set KSX_ALLOW_LOCAL_SANDBOX=1 on a dev "
                             "machine to accept running the target as an unisolated local subprocess")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(target_id: str, alive, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not alive():
            return False
        if allowlist.get(target_id, "/health", timeout=2).status == 200:
            return True
        time.sleep(0.25)
    return False


def stage_tree(source_dir: Path, dest: Path) -> Path:
    """Copy only the tracked source files (what the revision hash covers)."""
    dest.mkdir(parents=True, exist_ok=True)
    for p in source_dir.iterdir():
        if tracked(p):
            shutil.copyfile(p, dest / p.name)
    return dest


# -- launchers ----------------------------------------------------------------------

@contextmanager
def launch(code_dir: Path, fixture: seed.FixtureEnv, *, mode: str = "auto", source: str = DEFAULT_SOURCE,
           extra_env: dict | None = None):
    """Run the target from `code_dir`; yield (target_id, logs: dict). Always cleans up."""
    mode = choose_mode(mode)
    target_id = f"sbx-{uuid.uuid4().hex[:10]}"
    logs: dict = {"mode": mode}
    if mode == "local":
        with _launch_local(code_dir, fixture, target_id, logs, extra_env or {}):
            yield target_id, logs
    else:
        with _launch_docker(code_dir, fixture, target_id, logs, SOURCES[source], extra_env or {}):
            yield target_id, logs


@contextmanager
def _launch_local(code_dir: Path, fixture: seed.FixtureEnv, target_id: str, logs: dict, extra_env: dict):
    port = _free_port()
    keep = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "PYTHONPATH") if k in os.environ}
    env = {**keep, **fixture.env(), **extra_env, "KSX_HOST": "127.0.0.1", "KSX_PORT": str(port),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    out = tempfile.TemporaryFile()
    proc = subprocess.Popen([sys.executable, str(code_dir / "app.py")], cwd=str(code_dir), env=env,
                            stdout=out, stderr=subprocess.STDOUT)
    try:
        allowlist.register_ephemeral(target_id, f"http://127.0.0.1:{port}")
        logs["healthy"] = _wait_health(target_id, lambda: proc.poll() is None, HEALTH_TIMEOUT_S)
        yield
    finally:
        allowlist.unregister_ephemeral(target_id)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        out.seek(0)
        logs["exit_code"] = proc.returncode
        logs["output_excerpt"] = redact_text(out.read()[-4000:].decode("utf-8", "replace"))
        out.close()


def ensure_image(src: dict) -> None:
    if subprocess.run(["docker", "image", "inspect", src["image"]], capture_output=True).returncode == 0:
        return
    r = subprocess.run(["docker", "build", "-q", "-t", src["image"], str(src["dockerfile_dir"])],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise SandboxUnavailable(f"sandbox image build failed: {(r.stderr or r.stdout)[-400:]}")


@contextmanager
def _launch_docker(code_dir: Path, fixture: seed.FixtureEnv, target_id: str, logs: dict, src: dict, extra_env: dict):
    ensure_image(src)
    env_args = []
    for k, v in {"KSX_DB": "/fixture/demo.sqlite3", "KSX_DOC_ROOT": "/fixture/docs",
                 "KSX_FLAGS_FILE": "/fixture/flags.json", "KSX_HOST": "0.0.0.0",
                 "KSX_PORT": str(src["container_port"]), **extra_env}.items():
        env_args += ["-e", f"{k}={v}"]
    run = subprocess.run(
        ["docker", "run", "-d", "--rm", *DOCKER_LIMITS, "-p", f"127.0.0.1::{src['container_port']}",
         "--mount", f"type=bind,source={code_dir.resolve().as_posix()},target=/app,readonly",
         "--mount", f"type=bind,source={fixture.base_dir.resolve().as_posix()},target=/fixture,readonly",
         *env_args, src["image"]],
        capture_output=True, text=True, timeout=60)
    if run.returncode != 0:
        raise SandboxUnavailable(f"docker run failed: {run.stderr.strip()[:300]}")
    cid = run.stdout.strip()
    try:
        port_out = subprocess.run(["docker", "port", cid, str(src["container_port"])],
                                  capture_output=True, text=True).stdout.strip()
        host_port = port_out.splitlines()[0].rsplit(":", 1)[-1]
        allowlist.register_ephemeral(target_id, f"http://127.0.0.1:{host_port}")

        def alive():
            ps = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cid], capture_output=True, text=True)
            return ps.stdout.strip() == "true"

        logs["healthy"] = _wait_health(target_id, alive, HEALTH_TIMEOUT_S)
        logs["container_id"] = cid[:12]
        yield
    finally:
        allowlist.unregister_ephemeral(target_id)
        lg = subprocess.run(["docker", "logs", "--tail", "60", cid], capture_output=True, text=True)
        logs["output_excerpt"] = redact_text((lg.stdout + lg.stderr)[-4000:])
        subprocess.run(["docker", "stop", "-t", "2", cid], capture_output=True, text=True)


def oracle_for(fixture: seed.FixtureEnv, mode: str) -> OracleContext:
    spec = seed.load_spec()
    abs_sentinel = "/fixture/" + spec["sentinel"]["filename"] if mode == "docker" else str(fixture.sentinel_path)
    return OracleContext(canaries=fixture.canaries, canary_prefix=spec["canary_prefix"],
                         sentinel_token=fixture.sentinel_token, sentinel_prefix=spec["sentinel"]["prefix"],
                         sentinel_abs_path=abs_sentinel)


# -- patch store -----------------------------------------------------------------------

class PatchStore:
    def __init__(self, store: ArtifactStore | None = None):
        self.store = store or ArtifactStore()
        self.dir = self.store.root / "patches"

    def submit(self, patch_id: str, diff: str, base_revision: str, incident_id: str,
               source: str = DEFAULT_SOURCE) -> dict:
        safe_id(patch_id, "patch_id")
        safe_id(incident_id, "incident_id")
        if source not in SOURCES:
            raise patching.PatchRejected(f"unknown patch source {source!r}")
        touched = [f.path for f in patching.validate(diff, SOURCES[source]["allowed_files"])]
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / f"{patch_id}.json"
        record = {"patch_id": patch_id, "incident_id": incident_id, "source": source,
                  "base_revision": base_revision, "diff": diff, "diff_sha256": sha256_text(diff),
                  "touched_files": touched, "submitted_at_utc": utc_now()}
        if path.exists():
            prior = json.loads(path.read_text(encoding="utf-8"))
            if prior["diff_sha256"] != record["diff_sha256"]:
                raise patching.PatchRejected("patch_id already exists with different content; use a new patch_id")
            return prior
        path.write_text(json.dumps(record), encoding="utf-8")
        return record

    def get(self, patch_id: str) -> dict | None:
        p = self.dir / f"{safe_id(patch_id, 'patch_id')}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def base_revision(source: str = DEFAULT_SOURCE) -> str:
    return tree_revision(SOURCES[source]["source_dir"])


# -- patch test orchestration -------------------------------------------------------------

def _status(results: list[dict]) -> str:
    outcomes = [r["outcome"] for r in results]
    if not results:
        return "not_run"
    if any(o in {"infrastructure_error"} for o in outcomes) and not any(o == "patch_failed" for o in outcomes):
        return "infrastructure_error"
    if any(o in {"not_run", "revision_mismatch"} for o in outcomes):
        return "not_run"
    return "test_passed" if all(r["passed"] for r in results) else "test_failed"


def run_patch_tests_sync(patch_id: str, revision: str, test_ids: list[str], *, mode: str = "auto",
                         store: ArtifactStore | None = None, patches: PatchStore | None = None) -> dict:
    store = store or ArtifactStore()
    patches = patches or PatchStore(store)
    started = utc_now()
    report = {"patch_id": patch_id, "requested_revision": revision, "test_ids": test_ids,
              "started_at_utc": started, "status": "not_run", "results": [], "limitations": [
                  "Candidate patch tested in an ephemeral sandbox only; it is not merged or deployed.",
                  "Tests cover the registered exploit, functional and negative-input cases only."]}
    rec = patches.get(patch_id)
    if rec is None:
        report["reason"] = "unknown patch_id"
        return report
    incident_id = rec["incident_id"]
    report.update(incident_id=incident_id, diff_sha256=rec["diff_sha256"], base_revision=rec["base_revision"],
                  touched_files=rec["touched_files"])
    unknown = [t for t in test_ids if not registry.is_known(t)]
    if unknown or not test_ids:
        report["reason"] = f"unknown or empty test_ids: {unknown}"
        return _store_report(store, report)
    src = SOURCES[rec["source"]]
    current_base = tree_revision(src["source_dir"])
    if revision != rec["base_revision"] or revision != current_base:
        report["status"] = "not_run"
        report["reason"] = "revision_mismatch"
        report["limitations"].append(
            f"requested {revision}, patch written against {rec['base_revision']}, source is now {current_base}; "
            "results would be untrusted so nothing ran")
        return _store_report(store, report)

    with tempfile.TemporaryDirectory(prefix="ksx-patch-") as tmp:
        tmp = Path(tmp)
        code = stage_tree(src["source_dir"], tmp / "code")
        try:
            patching.apply(code, rec["diff"], src["allowed_files"])
        except patching.PatchRejected as e:
            report["reason"] = f"patch_rejected: {e}"
            return _store_report(store, report)
        patched_rev = tree_revision(code)
        report["patched_revision"] = patched_rev
        fixture = seed.build(tmp / "fixture", flags={"search_v1": True, "search_v2": False, "files_v1": True})
        try:
            with launch(code, fixture, mode=mode, source=rec["source"]) as (target_id, logs):
                report["sandbox"] = logs
                if not logs.get("healthy"):
                    report["status"] = "infrastructure_error"
                    report["reason"] = "patched target did not become healthy (it may crash on start)"
                else:
                    ctx = oracle_for(fixture, logs["mode"])
                    deadline = time.monotonic() + SANDBOX_TIMEOUT_S
                    for tid in test_ids:
                        if time.monotonic() > deadline:
                            report["results"].append({"test_id": tid, "outcome": "infrastructure_error",
                                                      "passed": False, "detail": "sandbox time budget exhausted"})
                            continue
                        report["results"].append(_run_one(tid, target_id, incident_id, patched_rev, ctx, store))
                    report["status"] = _status(report["results"])
        except SandboxUnavailable as e:
            report["status"] = "infrastructure_error"
            report["reason"] = str(e)
    report["tested_revision_matches"] = all(r.get("revision") in (None, patched_rev) for r in report["results"])
    if not report["tested_revision_matches"]:
        report["status"] = "not_run"
        report["reason"] = "tested revision differs from patched revision; results untrusted"
    return _store_report(store, report)


def _run_one(test_id: str, target_id: str, incident_id: str, patched_rev: str, ctx: OracleContext,
             store: ArtifactStore) -> dict:
    if registry.get_test(test_id):
        res = run_phase("after_patch", incident_id, test_id, target_id, ctx=ctx, revision=patched_rev, store=store)
        return {"test_id": test_id, "outcome": res.outcome, "passed": res.passed, "evidence_id": res.evidence_id,
                "revision": res.revision, "artifact_paths": res.artifact_paths,
                "checks": [c.model_dump() for c in res.checks + res.smoke], "limitations": res.limitations}
    checks: list[CheckResult] = probes.run_support(test_id, target_id, ctx)
    passed = bool(checks) and all(c.passed is True for c in checks)
    outcome = "patch_verified" if passed else (
        "infrastructure_error" if any(c.passed is None for c in checks) else "patch_failed")
    health = allowlist.get(target_id, "/health").json() or {}
    return {"test_id": test_id, "outcome": outcome, "passed": passed, "revision": health.get("revision"),
            "checks": [c.model_dump() for c in checks]}


def _store_report(store: ArtifactStore, report: dict) -> dict:
    report["finished_at_utc"] = utc_now()
    incident = report.get("incident_id") or "unassigned"
    identity = {k: report.get(k) for k in ("patch_id", "diff_sha256", "patched_revision", "status")}
    identity["results"] = [(r["test_id"], r["outcome"], r["passed"]) for r in report["results"]]
    ref = store.write(incident, f"patchtest-{report['patch_id']}", identity, {"report": report})
    report["evidence_id"] = ref.evidence_id
    report["artifact_path"] = ref.path
    return report


async def run_patch_tests(patch_id: str, revision: str, test_ids: list[str], **kw) -> dict:
    import asyncio
    return await asyncio.to_thread(run_patch_tests_sync, patch_id, revision, test_ids, **kw)


def run_request(req: TestRunRequest, **kw):
    """Entry point for a single registered test run against an allowlisted target."""
    return run_phase(req.phase, req.incident_id, req.test_id, req.target_id, revision=req.revision, **kw)
