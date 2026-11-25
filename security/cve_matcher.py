"""Dependency / advisory enrichment.

Matches package name + installed version + ecosystem against an advisory's
affected ranges (OSV format). A match means *potential relevance*. It never
makes a finding `reproduced`: exploitability needs a controlled test, and most
advisories have preconditions (a config, a feature, an exposed endpoint) that
the match alone cannot establish.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

from packaging.version import InvalidVersion, Version

from security.models import SecurityFinding
from security.revision import sha256_text

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ADVISORY_DIR = FIXTURES / "advisories"
SBOM_FIXTURE = FIXTURES / "sbom" / "demo-requirements.txt"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==\s*([^\s;]+))?", line)
        if not m:
            out.append({"package": line, "version": None, "note": "unparseable requirement line"})
            continue
        out.append({"package": m.group(1), "version": m.group(3),
                    "note": None if m.group(3) else "version not pinned; cannot match affected range"})
    return out


def _in_range(v: Version, events: list[dict]) -> bool | None:
    """OSV ECOSYSTEM range semantics. None = could not evaluate."""
    affected = False
    try:
        for ev in events:
            if "introduced" in ev:
                intro = ev["introduced"]
                if intro == "0" or v >= Version(intro):
                    affected = True
            elif "fixed" in ev:
                if v >= Version(ev["fixed"]):
                    affected = False
            elif "last_affected" in ev:
                if v > Version(ev["last_affected"]):
                    affected = False
            elif "limit" in ev:
                continue
            else:
                return None
    except InvalidVersion:
        return None
    return affected


def enrich_dependency_finding(package: str, version: str | None, advisory: dict,
                              ecosystem: str = "PyPI") -> dict:
    ctx = advisory.get("_ksx_fixture", {})
    base = {
        "package": package, "version": version, "ecosystem": ecosystem,
        "advisory_id": advisory.get("id"), "aliases": advisory.get("aliases", []),
        "summary": advisory.get("summary", ""), "published": advisory.get("published"),
        "modified": advisory.get("modified"),
        "severity": (advisory.get("database_specific") or {}).get("severity", "unknown"),
        "references": [r.get("url") for r in advisory.get("references", []) if r.get("url")],
        "source": ctx.get("source_url") or "live OSV record",
        "evidence_status": "suspected",
        "exploitability": "not_established",
        "exploit_preconditions": ctx.get("exploit_preconditions"),
        "uncertainty": [],
        "finding": None,
    }
    entries = [a for a in advisory.get("affected", [])
               if _norm(a.get("package", {}).get("name", "")) == _norm(package)
               and a.get("package", {}).get("ecosystem", "").lower() == ecosystem.lower()]
    if not entries:
        base.update(match="not_affected", match_reason="advisory does not list this package/ecosystem")
        return base
    if not version:
        base.update(match="unknown", match_reason="installed version unknown")
        base["uncertainty"].append("version information missing; pin versions to evaluate")
    else:
        try:
            v = Version(version)
        except InvalidVersion:
            v = None
        verdicts = []
        for a in entries:
            if version in a.get("versions", []):
                verdicts.append(True)
            for r in a.get("ranges", []):
                if r.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                    base["uncertainty"].append(f"range type {r.get('type')} not evaluated")
                    continue
                verdicts.append(_in_range(v, r.get("events", [])) if v else None)
        if any(x is True for x in verdicts):
            base.update(match="affected", match_reason=f"{package} {version} falls in an affected range")
        elif any(x is None for x in verdicts) or not verdicts:
            base.update(match="unknown", match_reason="affected range could not be evaluated")
            base["uncertainty"].append("affected-range parsing uncertain")
        else:
            base.update(match="not_affected", match_reason=f"{package} {version} is outside every affected range")
    if base["match"] in {"affected", "unknown"}:
        fp = sha256_text(f"dependency_cve|{package}|{version}|{advisory.get('id')}")[:16]
        sev = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
               "LOW": "low"}.get(str(base["severity"]).upper(), "unknown")
        base["finding"] = SecurityFinding(
            finding_id=f"fnd-{fp}", incident_id=f"inc-{fp[:10]}", category="dependency_cve",
            affected_component=f"{package}=={version}" if version else package, severity=sev,
            status="suspected", observed_behavior=f"advisory {advisory.get('id')} {base['match_reason']}",
            severity_rationale=f"advisory severity {base['severity']}; exploitability NOT established by a test",
            tool="cve_matcher", tool_version="1", raw_artifact=base["source"], fingerprint=fp,
            advisory={k: base[k] for k in ("advisory_id", "aliases", "published", "modified", "references",
                                           "exploit_preconditions", "match", "match_reason")},
        ).model_dump()
    return base


def load_advisories(directory: Path = ADVISORY_DIR) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]


def scan_requirements(path: Path = SBOM_FIXTURE, advisories: list[dict] | None = None) -> list[SecurityFinding]:
    advisories = advisories if advisories is not None else load_advisories()
    out = []
    for req in parse_requirements(path.read_text(encoding="utf-8")):
        for adv in advisories:
            e = enrich_dependency_finding(req["package"], req["version"], adv)
            if e["finding"]:
                out.append(SecurityFinding.model_validate(e["finding"]))
    return out


def fetch_osv(advisory_id: str, timeout: float = 10.0) -> dict:
    """Fetch the live OSV record (a public advisory database lookup, not a scan)."""
    if not re.match(r"^[A-Za-z0-9-]{5,40}$", advisory_id):
        raise ValueError("bad advisory id")
    req = urllib.request.Request(OSV_VULN_URL.format(id=advisory_id), headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def refresh_fixture(advisory_id: str) -> dict:
    """Compare the saved fixture with the live record; report differences, never overwrite silently."""
    saved = json.loads((ADVISORY_DIR / f"{advisory_id}.json").read_text(encoding="utf-8"))
    live = fetch_osv(advisory_id)
    diffs = {}
    for key in ("summary", "aliases", "published", "modified"):
        if saved.get(key) != live.get(key):
            diffs[key] = {"saved": saved.get(key), "live": live.get(key)}
    live_ranges = [r for a in live.get("affected", []) for r in a.get("ranges", [])]
    saved_ranges = [r for a in saved.get("affected", []) for r in a.get("ranges", [])]
    if live_ranges != saved_ranges:
        diffs["ranges"] = {"saved": saved_ranges, "live": live_ranges}
    return {"advisory_id": advisory_id, "matches_live": not diffs, "differences": diffs}
