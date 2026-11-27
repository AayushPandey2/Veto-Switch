"""Deterministic secret redaction preserving original artifact integrity."""

from __future__ import annotations

import re
from typing import Any

from shared.constants import REDACTED_PLACEHOLDER, SENSITIVE_FIELD_KEYWORDS
from shared.serialization import sha256_text

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(authorization\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)(x-ksx-token\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)(secret\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)(password\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)(session[_-]?(?:id|token)\s*[:=]\s*)([^\s,;\"']+)"),
    re.compile(r"(?i)((?:postgres(?:ql)?|mysql|sqlite|mongodb)(?:\+\w+)?://[^:\s]+:)([^@\s]+)(@)"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
)


def redact_text(value: str, *, tracker: list[str] | None = None) -> str:
    """Redact credentials, tokens, connection secrets, and private keys from text."""
    result = value
    for idx, pat in enumerate(_SECRET_PATTERNS):
        if idx == 7:
            new_val = pat.sub(rf"\1{REDACTED_PLACEHOLDER}\3", result)
        elif idx in (8, 9, 10, 11):
            new_val = pat.sub(REDACTED_PLACEHOLDER, result)
        else:
            new_val = pat.sub(rf"\1{REDACTED_PLACEHOLDER}", result)
        if new_val != result and tracker is not None:
            tracker.append("pattern_redacted")
        result = new_val
    return result


def redact_structured_data(
    data: Any,
    *,
    redacted_categories: list[str] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Recursively redact sensitive fields and values without mutating input."""
    categories = redacted_categories if redacted_categories is not None else []

    def _walk(node: Any, key_hint: str = "") -> Any:
        lower_key = key_hint.lower()
        if (
            any(kw in lower_key for kw in SENSITIVE_FIELD_KEYWORDS)
            and lower_key
            not in (
                "redaction_status",
                "redaction_summary",
                "redaction_policy_version",
                "authorization_context_ref",
            )
            and node is not None
            and node != ""
        ):
            categories.append(f"field:{key_hint}")
            return REDACTED_PLACEHOLDER
        if isinstance(node, dict):
            return {k: _walk(v, str(k)) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item, key_hint) for item in node]
        if isinstance(node, tuple):
            return [_walk(item, key_hint) for item in node]
        if isinstance(node, str):
            return redact_text(node, tracker=categories)
        return node

    sanitized = _walk(data)
    unique_cats = sorted(set(categories))
    summary = {
        "redaction_applied": len(unique_cats) > 0,
        "redacted_count": len(categories),
        "redacted_categories": unique_cats,
        "sanitized_export_sha256": sha256_text(str(sanitized)),
    }
    return sanitized, summary
