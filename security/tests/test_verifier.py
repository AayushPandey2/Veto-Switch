"""Phase verification against a live stand-in target (local subprocess, loopback only)."""

from __future__ import annotations

import asyncio

from security import allowlist, exploit_verifier, revision
from security.exploit_verifier import run_phase
from shared.schemas import VerificationResult

from .conftest import SOURCE_DIR


def test_sqli_baseline_reproduces(target, store):
    res = run_phase("before", "inc-t1", "sqli_search", target.target_id, ctx=target.ctx, store=store)
    assert isinstance(res, VerificationResult)
    assert res.outcome == "exploit_reproduced" and res.passed is True
    assert res.evidence_id and res.evidence_id.startswith("ev-verify-sqli_search-before-")
    assert res.observed_flag_state and "search_v1=on" in res.observed_flag_state
    assert any(c.passed is False and c.variant == "search_v1" for c in res.checks)
    assert "REPRODUCED" in res.phase_semantics
    assert store.read("inc-t1", res.evidence_id)["result"]["outcome"] == "exploit_reproduced"


def test_sqli_contained_after_flag_off_and_unrelated_routes_work(target, store):
    target.fixture.set_flags(search_v1=False)
    res = run_phase("after_containment", "inc-t2", "sqli_search", target.target_id, ctx=target.ctx, store=store)
    assert res.outcome == "contained" and res.passed is True
    assert res.observed_flags["search_v1"] is False
    fallback = next(c for c in res.checks if c.name == "safe_fallback")
    assert fallback.passed and fallback.variant == "search_fallback" and fallback.status_code == 503
    assert {s.route for s in res.smoke} == {"/status", "/catalog"} and all(s.passed for s in res.smoke)
    probed = {c.route for c in res.checks if c.name.startswith("exploit_probe")}
    assert probed == {"/search", "/legacy/search", "/search/"}


def test_sqli_before_with_flag_off_is_not_reproduced(make_target, store):
    t = make_target(flags={"search_v1": False, "search_v2": False, "files_v1": True})
    res = run_phase("before", "inc-t3", "sqli_search", t.target_id, ctx=t.ctx, store=store)
    assert res.outcome == "exploit_not_reproduced" and res.passed is False
    assert any("observed OFF" in lim for lim in res.limitations)


def test_traversal_baseline_and_containment(target, store):
    before = run_phase("before", "inc-t4", "traversal_files", target.target_id, ctx=target.ctx, store=store)
    assert before.outcome == "exploit_reproduced"
    target.fixture.set_flags(files_v1=False)
    after = run_phase("after_containment", "inc-t4", "traversal_files", target.target_id, ctx=target.ctx, store=store)
    assert after.outcome == "contained" and after.passed
    assert after.evidence_id != before.evidence_id


def test_flag_cache_lag_is_not_reported_as_contained(make_target, store):
    t = make_target(KSX_FLAG_CACHE_SECONDS=60)
    assert allowlist.get(t.target_id, "/health").json()["flags"]["search_v1"] is True  # warm the cache
    t.fixture.set_flags(search_v1=False)  # "Flagsmith write succeeded"
    res = run_phase("after_containment", "inc-t5", "sqli_search", t.target_id, ctx=t.ctx, store=store)
    assert res.passed is False
    assert res.outcome in {"containment_failed", "flag_mismatch"}
    assert any("did not observe the expected flag state" in lim for lim in res.limitations)


def test_alias_route_bypassing_flag_is_caught(make_target, store):
    t = make_target(KSX_BUG_ALIAS_BYPASS=1)
    t.fixture.set_flags(search_v1=False)
    res = run_phase("after_containment", "inc-t6", "sqli_search", t.target_id, ctx=t.ctx, store=store)
    assert res.outcome == "containment_failed" and res.passed is False
    assert any("/legacy/search" in lim for lim in res.limitations)


def test_blocked_by_other_variant_is_flag_mismatch_not_contained(make_target, store):
    # search_v2 wins, so the exploit is blocked, but search_v1 is still observed ON.
    t = make_target(flags={"search_v1": True, "search_v2": True, "files_v1": True})
    res = run_phase("after_containment", "inc-t7", "sqli_search", t.target_id, ctx=t.ctx, store=store)
    assert res.outcome == "flag_mismatch" and res.passed is False


def test_unreachable_target_is_infrastructure_error(local_sandbox, store):
    allowlist.register_ephemeral("sbx-dead", "http://127.0.0.1:9")  # nothing listens on the discard port
    try:
        res = run_phase("after_containment", "inc-t8", "sqli_search", "sbx-dead", store=store)
    finally:
        allowlist.unregister_ephemeral("sbx-dead")
    assert res.outcome == "infrastructure_error" and res.passed is False


def test_unknown_test_and_target_not_run(store):
    assert run_phase("before", "inc-t9", "rm_rf", "demo", store=store).outcome == "not_run"
    assert run_phase("before", "inc-t9", "sqli_search", "prod-db", store=store).outcome == "not_run"


def test_revision_mismatch_runs_nothing(target, store):
    res = run_phase("before", "inc-t10", "sqli_search", target.target_id, ctx=target.ctx,
                    revision="0" * 64, store=store)
    assert res.outcome == "revision_mismatch" and res.passed is False and res.checks == []


def test_app_revision_matches_sandbox_algorithm(target):
    reported = allowlist.get(target.target_id, "/health").json()["revision"]
    assert reported == revision.tree_revision(SOURCE_DIR)


def test_async_interface_and_events(target, store):
    res = asyncio.run(exploit_verifier.verify_vulnerability("inc-t11", "sqli_search", target.target_id,
                                                            ctx=target.ctx, store=store))
    (ev,) = exploit_verifier.result_events(res)
    assert ev.event_type == "verification_pass" and ev.payload["evidence_id"] == res.evidence_id
    assert ev.actor == "security-verifier"
