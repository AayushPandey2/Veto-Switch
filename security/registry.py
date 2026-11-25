"""Registry of approved security tests. Only these test IDs can run.

A test is bound to one category, one primary route plus its declared aliases,
the flag that guards it, and the flag state containment must produce. Route
aliases come from the demo app's route manifest; probing them is how we catch
"flag is off but another route still reaches the vulnerable handler".
"""

from __future__ import annotations

REGISTRY: dict[str, dict] = {
    "sqli_search": {
        "category": "sqli",
        "title": "SQL injection in /search exposes private documents",
        "route": "/search",
        "param": "q",
        # Declared alias + variants that naive route matching might miss.
        "route_variants": ["/search", "/legacy/search", "/search/"],
        "affected_component": "search_v1",
        "flag": "search_v1",
        "vulnerable_variant": "search_v1",
        "containment_expect": {"search_v1": False},
        "severity": "high",
        "severity_rationale": "Unauthenticated read of rows marked private (confidentiality). "
                              "Demo data only; no write or code-execution impact was tested.",
        "functional_tests": ["functional_search", "negative_inputs_search"],
        "smoke_tests": ["smoke_status", "smoke_catalog"],
        "timeout_s": 20,
    },
    "traversal_files": {
        "category": "path_traversal",
        "title": "Path traversal in /files reads outside the document root",
        "route": "/files",
        "param": "name",
        "route_variants": ["/files", "/files/"],
        "affected_component": "files_v1",
        "flag": "files_v1",
        "vulnerable_variant": "files_v1",
        "containment_expect": {"files_v1": False},
        "severity": "high",
        "severity_rationale": "Reads a file outside the allowed root (confidentiality). Proven with a "
                              "harmless sentinel file; reading arbitrary system files was not attempted.",
        "functional_tests": ["functional_files", "negative_inputs_files"],
        "smoke_tests": ["smoke_status", "smoke_catalog"],
        "timeout_s": 20,
    },
}

# Supporting tests runnable on their own (patch test runs, smoke checks).
SUPPORT_TESTS = {"functional_search", "negative_inputs_search", "functional_files",
                 "negative_inputs_files", "smoke_status", "smoke_catalog"}


def get_test(test_id: str) -> dict | None:
    return REGISTRY.get(test_id)


def is_known(test_id: str) -> bool:
    return test_id in REGISTRY or test_id in SUPPORT_TESTS


def test_for(category: str, route: str | None) -> str | None:
    """Map a scanner alert to the registered test that can confirm it (exact route match)."""
    for tid, spec in REGISTRY.items():
        if spec["category"] == category and route is not None and route in spec["route_variants"]:
            return tid
    return None


def public_view() -> dict:
    return {
        "security_tests": {tid: {k: v for k, v in spec.items()} for tid, spec in REGISTRY.items()},
        "support_tests": sorted(SUPPORT_TESTS),
    }
