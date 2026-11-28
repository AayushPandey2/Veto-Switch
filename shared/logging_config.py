"""Structured logging configuration and secret-redaction utilities for Killswitch X.

Security note:
    Redaction is defense-in-depth and NEVER a substitute for avoiding unnecessary
    sensitive data collection. Full LLM prompts containing source code or sensitive
    security evidence must not be logged by default.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from shared.constants import REDACTED_PLACEHOLDER, SENSITIVE_FIELD_KEYWORDS

_AUTH_HEADER_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?([A-Za-z0-9._~+/=-]{6,})"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{6,})")
_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passwd|secret|management_token|"
    r"session_token|signing_secret|private_key)\s*([:=])\s*(['\"]?)([^\s'\",;}{]+)\3"
)
_COMMON_TOKEN_PREFIX_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{8,}|fs_[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{10,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,})\b"
)

_RESERVED_RECORD_FIELDS: frozenset[str] = frozenset(
    {
        "incident_id",
        "correlation_id",
        "event_type",
        "operation_status",
        "diagnostic_context",
    }
)


def redact_text(value: str) -> str:
    """Scrub synthetic/live credentials, bearer tokens, and secret assignments from text."""
    redacted = _AUTH_HEADER_RE.sub(rf"\1\2{REDACTED_PLACEHOLDER}", value)
    redacted = _BEARER_RE.sub(rf"\1{REDACTED_PLACEHOLDER}", redacted)
    redacted = _KEY_VALUE_SECRET_RE.sub(rf"\1\2\3{REDACTED_PLACEHOLDER}\3", redacted)
    redacted = _COMMON_TOKEN_PREFIX_RE.sub(REDACTED_PLACEHOLDER, redacted)
    return redacted


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SENSITIVE_FIELD_KEYWORDS)


def redact_value(value: Any) -> Any:
    """Recursively redact sensitive fields in mappings, sequences, and strings."""
    if isinstance(value, Mapping):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deep-sanitized copy of a mapping with sensitive keys and values redacted."""
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        key_str = str(key)
        if _is_sensitive_key(key_str):
            sanitized[key_str] = REDACTED_PLACEHOLDER
        else:
            sanitized[key_str] = redact_value(value)
    return sanitized


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line UTC JSON objects with secret redaction."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z")
        )
        message = redact_text(record.getMessage())
        payload: dict[str, Any] = {
            "timestamp_utc": timestamp,
            "level": record.levelname,
            "module": record.name,
            "message": message,
        }
        for field in (
            "incident_id",
            "correlation_id",
            "event_type",
            "operation_status",
        ):
            val = getattr(record, field, None)
            if val is not None:
                payload[field] = redact_text(str(val))

        context = getattr(record, "diagnostic_context", None)
        if isinstance(context, Mapping):
            payload["context"] = redact_mapping(context)

        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))

        return json.dumps(payload, sort_keys=True, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-friendly UTC formatter for local development with secret redaction."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        message = redact_text(record.getMessage())
        parts = [f"{timestamp} [{record.levelname}] {record.name}: {message}"]
        incident_id = getattr(record, "incident_id", None)
        correlation_id = getattr(record, "correlation_id", None)
        event_type = getattr(record, "event_type", None)
        operation_status = getattr(record, "operation_status", None)
        meta: list[str] = []
        if incident_id:
            meta.append(f"incident={incident_id}")
        if correlation_id:
            meta.append(f"corr={correlation_id}")
        if event_type:
            meta.append(f"event={event_type}")
        if operation_status:
            meta.append(f"status={operation_status}")
        context = getattr(record, "diagnostic_context", None)
        if isinstance(context, Mapping) and context:
            meta.append(f"ctx={json.dumps(redact_mapping(context), sort_keys=True, default=str)}")
        if meta:
            parts.append(" | ".join(meta))
        return " ".join(parts)


def configure_logging(
    *,
    level: str = "INFO",
    log_format: str = "json",
    logger_name: str = "killswitch",
) -> logging.Logger:
    """Configure a namespaced Killswitch X logger with redacting structured output."""
    logger = logging.getLogger(logger_name)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(numeric_level)
    formatter: logging.Formatter = (
        ConsoleFormatter() if log_format.lower() == "console" else StructuredJsonFormatter()
    )
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_logger(name: str = "killswitch") -> logging.Logger:
    """Return a child logger under the configured ``killswitch`` namespace."""
    if name == "killswitch" or name.startswith("killswitch."):
        return logging.getLogger(name)
    return logging.getLogger(f"killswitch.{name}")


def log_structured(
    logger: logging.Logger,
    level: int,
    message: str,
    *,
    incident_id: str | None = None,
    correlation_id: str | None = None,
    event_type: str | None = None,
    operation_status: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> None:
    """Emit a structured log record with sanitized diagnostic context."""
    extra: dict[str, Any] = {
        "incident_id": incident_id,
        "correlation_id": correlation_id,
        "event_type": event_type,
        "operation_status": operation_status,
        "diagnostic_context": redact_mapping(context) if context else {},
    }
    logger.log(level, redact_text(message), extra=extra)
