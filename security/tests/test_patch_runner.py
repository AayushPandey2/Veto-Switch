"""Candidate patch runs: exploit regression + functional behaviour, revision-checked."""

from __future__ import annotations

from pathlib import Path

import pytest

from security import sandbox
from security.patching import PatchRejected

PATCHES = Path(__file__).resolve().parents[1] / "fixtures" / "patches"
SQLI_TESTS = ["sqli_search", "functional_search", "negative_inputs_search", "smoke_status"]


@pytest.fixture
def patches(store):
    return sandbox.PatchStore(store)


def _submit(patches, name, pid):
    rev = sandbox.base_revision()
    patches.submit(pid, (PATCHES / name).read_text(), rev, "inc-p")
    return rev


def test_sqli_fix_passes_security_and_functional(local_sandbox, store, patches):
    rev = _submit(patches, "sqli_fix.diff", "p-sqli")
    rep = sandbox.run_patch_tests_sync("p-sqli", rev, SQLI_TESTS, mode="local", store=store, patches=patches)
    assert rep["status"] == "test_passed", rep
    assert rep["patched_revision"] != rev and rep["tested_revision_matches"] is True
    assert rep["sandbox"]["mode"] == "local"
    assert all(r["passed"] for r in rep["results"])
    assert rep["evidence_id"] and any("NOT deployed" in lim for r in rep["results"] for lim in r.get("limitations", []))


def test_traversal_fix_passes(local_sandbox, store, patches):
    rev = _submit(patches, "traversal_fix.diff", "p-trav")
    rep = sandbox.run_patch_tests_sync("p-trav", rev, ["traversal_files", "functional_files", "negative_inputs_files"],
                                       mode="local", store=store, patches=patches)
    assert rep["status"] == "test_passed", rep


def test_original_code_fails_patch_phase(local_sandbox, store, patches):
    # A no-op patch (comment change) leaves the bug in place: must be test_failed.
    rev = sandbox.base_revision()
    src = (sandbox.SOURCES["stand_in"]["source_dir"] / "app.py").read_text().splitlines()
    idx = next(i for i, ln in enumerate(src) if ln.startswith("DEFAULT_FLAGS"))
    diff = (f"--- a/app.py\n+++ b/app.py\n@@ -{idx + 1},1 +{idx + 1},2 @@\n {src[idx]}\n+# cosmetic change\n")
    patches.submit("p-noop", diff, rev, "inc-p")
    rep = sandbox.run_patch_tests_sync("p-noop", rev, ["sqli_search"], mode="local", store=store, patches=patches)
    assert rep["status"] == "test_failed"
    assert rep["results"][0]["outcome"] == "patch_failed"


def test_patch_that_breaks_search_fails(local_sandbox, store, patches):
    rev = _submit(patches, "sqli_fix_breaks_search.diff", "p-broken")
    rep = sandbox.run_patch_tests_sync("p-broken", rev, SQLI_TESTS, mode="local", store=store, patches=patches)
    assert rep["status"] == "test_failed"
    by_id = {r["test_id"]: r for r in rep["results"]}
    assert by_id["functional_search"]["passed"] is False
    assert any("breaks normal behaviour" in lim for lim in by_id["sqli_search"]["limitations"])


def test_stale_revision_runs_nothing(local_sandbox, store, patches):
    _submit(patches, "sqli_fix.diff", "p-stale")
    rep = sandbox.run_patch_tests_sync("p-stale", "f" * 64, SQLI_TESTS, mode="local", store=store, patches=patches)
    assert rep["status"] == "not_run" and rep["reason"] == "revision_mismatch" and rep["results"] == []


def test_outside_allowlist_refused_at_submission(patches):
    with pytest.raises(PatchRejected):
        patches.submit("p-out", (PATCHES / "outside_allowlist.diff").read_text(), sandbox.base_revision(), "inc-p")


def test_patch_id_reuse_with_different_content_refused(patches):
    _submit(patches, "sqli_fix.diff", "p-dup")
    with pytest.raises(PatchRejected, match="already exists"):
        patches.submit("p-dup", (PATCHES / "traversal_fix.diff").read_text(), sandbox.base_revision(), "inc-p")


def test_unknown_test_id_not_run(store, patches):
    rev = _submit(patches, "sqli_fix.diff", "p-unk")
    rep = sandbox.run_patch_tests_sync("p-unk", rev, ["curl_anything"], store=store, patches=patches)
    assert rep["status"] == "not_run"


def test_no_sandbox_available_is_infrastructure_error(monkeypatch, store, patches):
    monkeypatch.delenv("KSX_ALLOW_LOCAL_SANDBOX", raising=False)
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    rev = _submit(patches, "sqli_fix.diff", "p-nosbx")
    rep = sandbox.run_patch_tests_sync("p-nosbx", rev, SQLI_TESTS, store=store, patches=patches)
    assert rep["status"] == "infrastructure_error" and "no sandbox available" in rep["reason"]


@pytest.mark.docker
def test_sqli_fix_in_docker(store, patches):
    if not sandbox.docker_available():
        pytest.skip("Docker daemon not available")
    rev = _submit(patches, "sqli_fix.diff", "p-docker")
    rep = sandbox.run_patch_tests_sync("p-docker", rev, SQLI_TESTS, mode="docker", store=store, patches=patches)
    assert rep["sandbox"]["mode"] == "docker"
    assert rep["status"] == "test_passed", rep
