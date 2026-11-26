"""Utilities for loading JSON fixtures from ``shared/fixtures/``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).resolve().parent


def load_fixture_file(filename: str) -> dict[str, Any]:
    """Load a fixture JSON file from ``shared/fixtures/`` as a dictionary."""
    target = FIXTURES_DIR / filename
    if not target.exists():
        raise FileNotFoundError(f"Fixture file not found: {target}")
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Fixture root must be a JSON object: {target}")
    return data
