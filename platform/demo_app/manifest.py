"""Stable route and feature-flag metadata for the synthetic demo."""

ROUTE_MANIFEST = [
    {
        "path": "/search",
        "method": "GET",
        "flags": ["search_v1", "search_v2"],
        "safe_variant": "search_v2",
        "fallback": "parameterized synthetic search",
    },
    {
        "path": "/files",
        "method": "GET",
        "flags": ["files_v1", "files_v2"],
        "safe_variant": "files_v2",
        "fallback": "public in-memory demo files only",
    },
    {
        "path": "/status",
        "method": "GET",
        "flags": [],
        "safe_variant": None,
        "fallback": "unrelated health route",
    },
]

DEMO_ONLY_ROUTES = ["/demo/search-v1", "/demo/files-v1"]
