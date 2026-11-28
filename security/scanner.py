"""Scanner adapters and finding normalization.

Adapters turn tool output (SARIF from Semgrep/ExhibitA, or a saved fixture) into
`SecurityFinding`s. Anything a scanner reports is `suspected`. A finding becomes
`reproduced` only when a registered exploit test reproduces it on an allowlisted
target and attaches the evidence ID. Findings are deduplicated by fingerprint
(category + route + component + rule), so repeated reports merge.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from security import registry
from security.evidence import ArtifactStore, event
from security.exploit_verifier import run_phase
from security.models import SecurityFinding
from security.probes import OracleContext
from security.revision import sha256_text

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Map common rule identifiers / CWE tags to our categories.
_CATEGORY_HINTS = [
    ("sqli", ("sql", "cwe-89")),
    ("path_traversal", ("path-traversal", "path_traversal", "traversal", "cwe-22")),
]


def categorize(*texts: str) -> str:
    blob = " ".join(t.lower() for t in texts if t)
    for cat, hints in _CATEGORY_HINTS:
        if any(h in blob for h in hints):
            return cat
    return "other"


def fingerprint(category: str, route: str | None, component: str | None, rule: str) -> str:
    return sha256_text(f"{category}|{route}|{component}|{rule}")[:16]


def incident_for(fp: str) -> str:
    return f"inc-{fp[:10]}"


class ScannerAdapter(ABC):
    name: str = "adapter"

    @abstractmethod
    def findings(self) -> list[SecurityFinding]:
        ...


class SarifAdapter(ScannerAdapter):
    """SARIF 2.1.0 output (Semgrep --sarif, ExhibitA --sarif).

    Route attribution uses `properties.route` on the result when the producing tool
    sets it; otherwise the finding has no route and cannot be auto-confirmed.
    """

    def __init__(self, sarif: dict, artifact_ref: str | None = None, route_hints: dict | None = None):
        self.sarif = sarif
        self.artifact_ref = artifact_ref
        self.route_hints = route_hints or {}   # "file:line" -> route, from the app's route manifest

    @classmethod
    def from_file(cls, path: str | Path, **kw) -> "SarifAdapter":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")), artifact_ref=str(path), **kw)

    def findings(self) -> list[SecurityFinding]:
        out = []
        for run in self.sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            tool, version = driver.get("name", "unknown"), driver.get("semanticVersion") or driver.get("version", "")
            rules = {r.get("id"): r for r in driver.get("rules", [])}
            for res in run.get("results", []):
                rule_id = res.get("ruleId", "")
                rule = rules.get(rule_id, {})
                tags = " ".join(rule.get("properties", {}).get("tags", []))
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                file = loc.get("artifactLocation", {}).get("uri", "")
                line = loc.get("region", {}).get("startLine")
                props = res.get("properties", {})
                route = props.get("route") or self.route_hints.get(f"{file}:{line}")
                category = categorize(rule_id, tags, res.get("message", {}).get("text", ""))
                component = props.get("component") or (f"{file}:{line}" if file else None)
                fp = fingerprint(category, route, component, rule_id)
                out.append(SecurityFinding(
                    finding_id=f"fnd-{fp}", incident_id=incident_for(fp), category=category,
                    affected_route=route, affected_component=component,
                    severity=_sarif_severity(res.get("level"), rule), status="suspected",
                    observed_behavior=f"static alert {rule_id}: {res.get('message', {}).get('text', '')[:200]}",
                    severity_rationale="scanner-reported severity; not yet confirmed by a controlled test",
                    tool=tool, tool_version=str(version), raw_artifact=self.artifact_ref, fingerprint=fp,
                ))
        return out


def _sarif_severity(level: str | None, rule: dict) -> str:
    sec = rule.get("properties", {}).get("security-severity")
    if sec is not None:
        s = float(sec)
        return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
    return {"error": "high", "warning": "medium", "note": "low"}.get(level or "", "unknown")


class FixtureAdapter(SarifAdapter):
    """Saved scanner output for reliable demos when a live scanner is unavailable."""
    name = "fixture"

    def __init__(self, path: str | Path = FIXTURES / "scanner" / "demo_scan.sarif.json"):
        super().__init__(json.loads(Path(path).read_text(encoding="utf-8")),
                         artifact_ref=f"fixture:{Path(path).name}")


def dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    merged: dict[str, SecurityFinding] = {}
    for f in findings:
        if f.fingerprint in merged:
            m = merged[f.fingerprint]
            m.evidence_ids = sorted(set(m.evidence_ids) | set(f.evidence_ids))
            if f.status == "reproduced":
                m.status = "reproduced"
        else:
            merged[f.fingerprint] = f.model_copy(deep=True)
    return list(merged.values())


def confirm(f: SecurityFinding, target_id: str, *, ctx: OracleContext | None = None,
            store: ArtifactStore | None = None) -> tuple[SecurityFinding, list]:
    """Try to reproduce a suspected finding with its registered test. Never upgrades without proof."""
    test_id = registry.test_for(f.category, f.affected_route)
    if test_id is None:
        f.observed_behavior += " | no registered reproduction test for this category/route; stays suspected"
        return f, [event(f.incident_id, "finding_suspected", {"finding_id": f.finding_id, "reason": "no_test"})]
    res = run_phase("before", f.incident_id, test_id, target_id, ctx=ctx, store=store)
    spec = registry.get_test(test_id)
    f.test_id, f.target_id = test_id, target_id
    if res.evidence_id:
        f.evidence_ids = sorted(set(f.evidence_ids) | {res.evidence_id})
    if res.outcome == "exploit_reproduced":
        f.status = "reproduced"
        f.severity = spec["severity"]
        f.severity_rationale = spec["severity_rationale"]
        f.affected_component = spec["affected_component"]
        f.observed_behavior = (f"{spec['title']}: controlled test {test_id} returned fixture data that the "
                               f"route must not expose (variant {_variant(res)}).")
        etype = "finding_reproduced"
    else:
        f.observed_behavior += f" | reproduction attempt: {res.outcome}"
        etype = "finding_suspected"
    return f, [event(f.incident_id, etype, {"finding_id": f.finding_id, "test_id": test_id,
                                            "outcome": res.outcome, "evidence_id": res.evidence_id})]


def _variant(res) -> str:
    for c in res.checks:
        if c.passed is False:
            return c.variant or "unknown"
    return "unknown"


def scan_demo_sync(target_id: str, adapters: list[ScannerAdapter] | None = None, *,
                   ctx: OracleContext | None = None, store: ArtifactStore | None = None,
                   include_dependencies: bool = True) -> tuple[list[SecurityFinding], list]:
    adapters = adapters if adapters is not None else [FixtureAdapter()]
    raw = [f for a in adapters for f in a.findings()]
    findings, events = [], []
    for f in dedupe(raw):
        f, evs = confirm(f, target_id, ctx=ctx, store=store)
        findings.append(f)
        events += evs
    if include_dependencies:
        from security.cve_matcher import scan_requirements
        for f in scan_requirements():
            findings.append(f)
            events.append(event(f.incident_id, "finding_suspected",
                                {"finding_id": f.finding_id, "reason": "dependency advisory match only"}))
    return findings, events


async def scan_demo(target_id: str, **kw) -> list[SecurityFinding]:
    import asyncio
    findings, _ = await asyncio.to_thread(scan_demo_sync, target_id, **kw)
    return findings
