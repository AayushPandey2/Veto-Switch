"""Canonical serialization, SHA-256 hashing, and Pydantic JSON helpers.

Deterministic hashing guarantees that identical security-relevant payloads produce
identical SHA-256 digests regardless of dictionary key ordering or whitespace,
enabling exact proposal identity binding between AI proposals and human approvals.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

from pydantic import BaseModel

from shared.constants import CANONICAL_PROPOSAL_HASH_FIELDS
from shared.exceptions import ContractValidationError
from shared.identifiers import format_utc_iso

ModelT = TypeVar("ModelT", bound=BaseModel)


def _normalize_for_canonical_json(value: Any) -> Any:
    """Recursively normalize Python values into deterministic JSON-compatible types."""
    if isinstance(value, BaseModel):
        return _normalize_for_canonical_json(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return format_utc_iso(value)
    if isinstance(value, Mapping):
        return {
            str(k): _normalize_for_canonical_json(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_for_canonical_json(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ContractValidationError(
        f"Unsupported type for canonical JSON serialization: {type(value).__name__}",
        context={"value_type": type(value).__name__},
    )


def canonical_json(data: Any) -> str:
    """Serialize data into compact, sorted-key, UTF-8 canonical JSON."""
    normalized = _normalize_for_canonical_json(data)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_bytes(content: bytes) -> str:
    """Return lowercase hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(content).hexdigest()


def sha256_text(text: str) -> str:
    """Return lowercase hex SHA-256 digest of UTF-8 encoded text."""
    return sha256_bytes(text.encode("utf-8"))


def sha256_canonical(data: Any) -> str:
    """Return lowercase hex SHA-256 digest of the canonical JSON representation."""
    return sha256_text(canonical_json(data))


def compute_proposal_hash(proposal_fields: Mapping[str, Any]) -> str:
    """Compute canonical SHA-256 hash over all security-relevant containment proposal fields.

    Canonical fields (in ``shared.constants.CANONICAL_PROPOSAL_HASH_FIELDS``):
        ``proposal_id``, ``incident_id``, ``proposal_type``, ``environment``,
        ``flag_name``, ``desired_enabled``, ``expected_current_enabled``,
        ``registry_version``, ``policy_version``, ``approval_required``,
        ``idempotency_token``.

    Raises:
        ContractValidationError: If any canonical proposal field is missing.
    """
    missing = [f for f in CANONICAL_PROPOSAL_HASH_FIELDS if f not in proposal_fields]
    if missing:
        raise ContractValidationError(
            "Missing required fields for canonical proposal hash computation.",
            context={"missing_fields": missing},
        )
    canonical_payload = {field: proposal_fields[field] for field in CANONICAL_PROPOSAL_HASH_FIELDS}
    return sha256_canonical(canonical_payload)


def to_json(model: BaseModel, *, indent: int | None = None) -> str:
    """Serialize a Pydantic model to JSON using canonical field names and UTC ISO strings."""
    return model.model_dump_json(indent=indent)


def from_json(model_cls: type[ModelT], raw: str | bytes) -> ModelT:
    """Deserialize and strictly validate JSON into the specified Pydantic model class."""
    return model_cls.model_validate_json(raw)
