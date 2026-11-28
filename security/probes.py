"""Individual security, functional and smoke checks against an allowlisted target.

The verdicts use deterministic fixture oracles: a private canary row or an
outside-root sentinel file can only appear in a response if the boundary was
crossed. A boolean-difference check (ported from ExhibitA's generic DAST
oracle) is recorded as corroboration only; it never decides a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from security import allowlist
from security.models import CheckResult
from security.seed import load_spec


@dataclass
class OracleContext:
    """What the oracle looks for. Exact values for owned launches, prefixes otherwise."""
    canaries: list[str] = field(default_factory=list)
    canary_prefix: str = ""
    sentinel_token: str | None = None
    sentinel_prefix: str = ""
    sentinel_abs_path: str | None = None
    identity: str = "demo-user-01"

    @classmethod
    def from_spec(cls) -> "OracleContext":
        spec = load_spec()
        return cls(canary_prefix=spec["canary_prefix"], sentinel_prefix=spec["sentinel"]["prefix"])

    def leaked_canary(self, body: str) -> bool:
        return any(c in body for c in self.canaries) or bool(self.canary_prefix and self.canary_prefix in body)

    def leaked_sentinel(self, body: str) -> bool:
        if self.sentinel_token and self.sentinel_token in body:
            return True
        return bool(self.sentinel_prefix and self.sentinel_prefix in body)


def _headers(ctx: OracleContext) -> dict:
    return {"X-Demo-User": ctx.identity}


def _excerpt(body: str, n: int = 240) -> str:
    return body[:n] + ("..." if len(body) > n else "")


# -- exploit probes ------------------------------------------------------------

# Inputs that turn the vulnerable WHERE clause into a tautology. They only ever
# run against allowlisted fixture targets.
SQLI_PROBES = ["zzz' OR 1=1 OR '", "' OR 1=1 --"]
SQLI_BOOLEAN_PAIR = ("zzz' OR 1=1 OR '", "zzz' AND 1=2 AND '")


def traversal_probes(ctx: OracleContext, sentinel_filename: str) -> list[str]:
    probes = [f"../{sentinel_filename}", f"./../{sentinel_filename}", f"..\\{sentinel_filename}"]
    if ctx.sentinel_abs_path:
        probes.append(ctx.sentinel_abs_path)
    return probes


def exploit_probes(target_id: str, test_id: str, spec: dict, ctx: OracleContext,
                   routes: list[str]) -> list[CheckResult]:
    """Try the exploit on each route. passed=True means the boundary HELD on that probe."""
    results = []
    param = spec["param"]
    if test_id == "sqli_search":
        payloads, leaked = SQLI_PROBES, ctx.leaked_canary
    else:
        payloads = traversal_probes(ctx, load_spec()["sentinel"]["filename"])
        leaked = ctx.leaked_sentinel
    for route in routes:
        for i, value in enumerate(payloads):
            r = allowlist.get(target_id, route, {param: value}, headers=_headers(ctx))
            if r.status == 0:
                results.append(CheckResult(name=f"exploit_probe[{i}]", passed=None, route=route,
                                           detail=f"no response: {r.error}"))
                continue
            hit = leaked(r.body)
            results.append(CheckResult(
                name=f"exploit_probe[{i}]", passed=not hit, route=route, status_code=r.status,
                variant=r.variant,
                detail=("boundary crossed: fixture canary/sentinel present in response"
                        if hit else f"no fixture canary/sentinel in response ({_excerpt(r.body, 80)})"),
            ))
    return results


def boolean_diff_corroboration(target_id: str, spec: dict, ctx: OracleContext) -> CheckResult:
    """Ported ExhibitA diff oracle: true vs false condition responses differ (payload text stripped)."""
    t, f = SQLI_BOOLEAN_PAIR
    rt = allowlist.get(target_id, spec["route"], {spec["param"]: t}, headers=_headers(ctx))
    rf = allowlist.get(target_id, spec["route"], {spec["param"]: f}, headers=_headers(ctx))
    if rt.status == 0 or rf.status == 0:
        return CheckResult(name="corroboration_boolean_diff", passed=None, route=spec["route"],
                           detail="not run: no response")
    nt, nf = rt.body.replace(t, ""), rf.body.replace(f, "")
    differs = nt != nf and abs(len(nt) - len(nf)) > 8
    return CheckResult(name="corroboration_boolean_diff", passed=None, route=spec["route"],
                       detail=("true/false conditions produced different responses (corroborates injection)"
                               if differs else "no boolean difference observed"))


# -- functional, negative-input and smoke checks --------------------------------

def _check(name: str, route: str, r: allowlist.Response, ok: bool, detail: str) -> CheckResult:
    if r.status == 0:
        return CheckResult(name=name, passed=None, route=route, detail=f"no response: {r.error}")
    return CheckResult(name=name, passed=ok, route=route, status_code=r.status, variant=r.variant, detail=detail)


def functional_search(target_id: str, ctx: OracleContext) -> list[CheckResult]:
    fs = load_spec()["functional_search"]
    r = allowlist.get(target_id, "/search", {"q": fs["query"]}, headers=_headers(ctx))
    data = r.json() or {}
    titles = sorted(x.get("title", "") for x in data.get("results", []))
    ok = r.status == 200 and titles == sorted(fs["expected_titles"]) and not ctx.leaked_canary(r.body)
    return [_check("functional_search", "/search", r, ok,
                   f"query {fs['query']!r} returned {len(titles)} titles; expected {len(fs['expected_titles'])}")]


def negative_inputs_search(target_id: str, ctx: OracleContext) -> list[CheckResult]:
    cases = [
        ("apostrophe_in_benign_query", "O'Brien", lambda d: any("O'Brien" in x["title"] for x in d.get("results", []))),
        ("empty_query", "", lambda d: isinstance(d.get("results"), list)),
        ("wildcard_char", "%", lambda d: isinstance(d.get("results"), list)),
        ("long_query", "w" * 2000, lambda d: d.get("results") == []),
        ("unicode_query", "wïdget", lambda d: isinstance(d.get("results"), list)),
    ]
    out = []
    for name, q, pred in cases:
        r = allowlist.get(target_id, "/search", {"q": q}, headers=_headers(ctx))
        data = r.json() or {}
        ok = r.status == 200 and pred(data) and not ctx.leaked_canary(r.body)
        out.append(_check(f"negative_input:{name}", "/search", r, ok, f"status {r.status}"))
    return out


def functional_files(target_id: str, ctx: OracleContext) -> list[CheckResult]:
    ff = load_spec()["functional_file"]
    r = allowlist.get(target_id, "/files", {"name": ff["name"]}, headers=_headers(ctx))
    ok = r.status == 200 and ff["expected_substring"] in r.body
    return [_check("functional_files", "/files", r, ok, f"valid fixture file {ff['name']!r}: status {r.status}")]


def negative_inputs_files(target_id: str, ctx: OracleContext) -> list[CheckResult]:
    cases = [("empty_name", ""), ("missing_file", "does-not-exist.txt"), ("parent_dir_only", "../"),
             ("nested_escape", "a/../../" + load_spec()["sentinel"]["filename"])]
    out = []
    for name, value in cases:
        r = allowlist.get(target_id, "/files", {"name": value}, headers=_headers(ctx))
        ok = 400 <= r.status < 500 and not ctx.leaked_sentinel(r.body)
        out.append(_check(f"negative_input:{name}", "/files", r, ok, f"expected 4xx, got {r.status}"))
    return out


def smoke_status(target_id: str, ctx: OracleContext) -> list[CheckResult]:
    r = allowlist.get(target_id, "/status", headers=_headers(ctx))
    return [_check("smoke_status", "/status", r, r.status == 200 and (r.json() or {}).get("status") == "ok",
                   f"unrelated route /status: {r.status}")]


def smoke_catalog(target_id: str, ctx: OracleContext) -> list[CheckResult]:
    r = allowlist.get(target_id, "/catalog", headers=_headers(ctx))
    n = len((r.json() or {}).get("items", []))
    return [_check("smoke_catalog", "/catalog", r, r.status == 200 and n == len(load_spec()["catalog"]),
                   f"unrelated route /catalog: {r.status}, {n} items")]


def fallback_check(target_id: str, test_id: str, spec: dict, ctx: OracleContext) -> CheckResult:
    """With the flag off, a benign request must take a safe path and leak nothing."""
    if test_id == "sqli_search":
        r = allowlist.get(target_id, "/search", {"q": load_spec()["functional_search"]["query"]}, headers=_headers(ctx))
        leaked = ctx.leaked_canary(r.body)
    else:
        r = allowlist.get(target_id, "/files", {"name": load_spec()["functional_file"]["name"]}, headers=_headers(ctx))
        leaked = ctx.leaked_sentinel(r.body)
    safe = r.variant != spec["vulnerable_variant"] and not leaked
    return _check("safe_fallback", spec["route"], r, safe,
                  f"benign request served by variant {r.variant!r}, status {r.status}"
                  + ("; FALLBACK LEAKED FIXTURE DATA" if leaked else ""))


SUPPORT = {
    "functional_search": functional_search,
    "negative_inputs_search": negative_inputs_search,
    "functional_files": functional_files,
    "negative_inputs_files": negative_inputs_files,
    "smoke_status": smoke_status,
    "smoke_catalog": smoke_catalog,
}


def run_support(test_id: str, target_id: str, ctx: OracleContext) -> list[CheckResult]:
    return SUPPORT[test_id](target_id, ctx)
