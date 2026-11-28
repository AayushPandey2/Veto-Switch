"""Intentionally vulnerable path resolver for synthetic local demo data only."""

import posixpath

from demo_app.file_service import DEMO_FILES


def vulnerable_read_demo_file_for_demo(requested_path: str) -> str | None:
    """Demonstrate path traversal without opening or reading disk files."""
    normalized = requested_path.replace("\\", "/")
    candidate = posixpath.normpath(posixpath.join("public", normalized))
    return DEMO_FILES.get(candidate)
