"""Scrub secrets and secret-looking strings before anything is logged or stored."""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS = [
    re.compile(r"\bser\.[A-Za-z0-9_\-]{8,}"),                      # Flagsmith server-side env keys
    re.compile(r"\bKSX_DUMMY_TOKEN_[A-Za-z0-9_\-]+"),             # injected dummy tokens in fixtures
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-~+/]{8,}=*"),
    re.compile(r"(?i)\b(token|api[_-]?key|secret|password|passwd|authorization|x-ksx-token)"
               r"(\s*[:=]\s*|\"\s*:\s*\")[^\s\"',&]{4,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                          # AWS access key id shape
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),                # GitHub token shape
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),  # JWT shape
]

_SENSITIVE_KEYS = {"token", "api_key", "apikey", "secret", "password", "authorization",
                   "x-ksx-token", "cookie", "set-cookie", "session"}


def redact_text(text: str) -> str:
    for pat in _PATTERNS:
        if pat.groups >= 2:
            text = pat.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
        else:
            text = pat.sub(REDACTED, text)
    return text


def redact(obj: Any) -> Any:
    """Recursively redact strings; values under sensitive keys are dropped entirely."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: (REDACTED if str(k).lower() in _SENSITIVE_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj
