from __future__ import annotations

import json

import pytest

from security import cve_matcher, scanner
from security.evidence import ArtifactStore, evidence_id
from security.models import SecurityFinding
from security.redact import redact, redact_text

ADV = json.loads((cve_matcher.ADVISORY_DIR / "GHSA-2g68-c3qc-8985.json").read_text(encoding="utf-8"))


# -- scanner ----------------------------------------------------------------------

def test_fixture_scan_reproduces_planted_bugs_and_dedupes(target, store):
    findings, events = scanner.scan_demo_sync(target.target_id, ctx=target.ctx, store=store)
    assert all(isinstance(f, SecurityFinding) for f in findings)
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    assert len(by_cat["sqli"]) == 1  # duplicate SARIF result merged
    sqli = by_cat["sqli"][0]
    assert sqli.status == "reproduced" and sqli.test_id == "sqli_search" and sqli.evidence_ids
    assert sqli.affected_route == "/search" and sqli.severity == "high" and sqli.severity_rationale
    assert by_cat["path_traversal"][0].status == "reproduced"
    assert by_cat["other"][0].status == "suspected"          # weak hash: no reproduction test
    assert by_cat["dependency_cve"][0].status == "suspected"  # advisory match only
    assert {e.event_type for e in events} >= {"finding_reproduced", "finding_suspected"}


def test_finding_without_reproduction_stays_suspected(make_target, store):
    t = make_target(flags={"search_v1": False, "search_v2": False, "files_v1": False})
    findings, _ = scanner.scan_demo_sync(t.target_id, ctx=t.ctx, store=store, include_dependencies=False)
    assert findings and all(f.status == "suspected" for f in findings)


def test_categorize():
    assert scanner.categorize("tainted-sql-string") == "sqli"
    assert scanner.categorize("x", "CWE-22: Path Traversal") == "path_traversal"


# -- CVE enrichment ----------------------------------------------------------------

def test_affected_version_is_suspected_never_reproduced():
    e = cve_matcher.enrich_dependency_finding("Werkzeug", "2.3.7", ADV)
    assert e["match"] == "affected" and e["evidence_status"] == "suspected"
    assert e["exploitability"] == "not_established" and e["exploit_preconditions"]
    assert e["finding"]["status"] == "suspected" and e["finding"]["category"] == "dependency_cve"
    assert "CVE-2024-34069" in e["aliases"] and e["published"]


@pytest.mark.parametrize("version,match", [("3.0.3", "not_affected"), ("3.1.9", "not_affected"),
                                           (None, "unknown"), ("not-a-version", "unknown")])
def test_version_edge_cases(version, match):
    e = cve_matcher.enrich_dependency_finding("werkzeug", version, ADV)
    assert e["match"] == match
    if match == "unknown":
        assert e["uncertainty"] and e["finding"]["status"] == "suspected"


def test_other_package_not_matched():
    assert cve_matcher.enrich_dependency_finding("flask", "2.3.2", ADV)["match"] == "not_affected"


def test_requirements_parsing_flags_unpinned():
    reqs = cve_matcher.parse_requirements("flask==2.3.2\nitsdangerous\n# c\n")
    assert reqs[1]["version"] is None and "not pinned" in reqs[1]["note"]


@pytest.mark.network
def test_fixture_matches_live_osv():
    assert cve_matcher.refresh_fixture("GHSA-2g68-c3qc-8985")["matches_live"]


# -- redaction and evidence ----------------------------------------------------------

def test_redaction():
    s = redact_text("key ser.abcdefgh12345 and KSX_DUMMY_TOKEN_xyz and Authorization: Bearer abc.def.ghi123")
    assert "ser.abcdefgh" not in s and "KSX_DUMMY_TOKEN_xyz" not in s and "abc.def.ghi123" not in s
    assert redact({"api_key": "x", "nested": {"password": "y"}, "ok": "fine"}) == \
        {"api_key": "[REDACTED]", "nested": {"password": "[REDACTED]"}, "ok": "fine"}


def test_artifacts_are_redacted_stable_and_tamper_evident(tmp_path):
    store = ArtifactStore(tmp_path)
    ident = {"obs": 1}
    ref = store.write("inc-e", "verify-x", ident, {"log": "token=KSX_DUMMY_TOKEN_secret123"})
    again = store.write("inc-e", "verify-x", ident, {"log": "different payload, same observations"})
    assert again == ref and ref.evidence_id == evidence_id("verify-x", ident)
    assert "KSX_DUMMY_TOKEN_secret123" not in (tmp_path / ref.path).read_text()
    assert store.verify_integrity("inc-e") == [{"evidence_id": ref.evidence_id, "path": ref.path, "intact": True}]
    (tmp_path / ref.path).write_text("{}")
    assert store.verify_integrity("inc-e")[0]["intact"] is False


def test_unsafe_incident_ids_refused(tmp_path):
    with pytest.raises(ValueError):
        ArtifactStore(tmp_path).write("../escape", "k", {}, {})
