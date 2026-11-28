"""Bounded in-memory AI investigation cache with strict scope & invalidation hygiene."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from shared.constants import POLICY_VERSION, SCHEMA_VERSION
from shared.enums import AITaskType
from shared.serialization import sha256_canonical


@dataclass(frozen=True)
class CacheKeyInput:
    """All dimensions determining whether a validated AI result may be safely reused."""

    task_type: AITaskType
    incident_id: str
    authorization_scope: str
    finding_hash: str
    evidence_hashes: tuple[str, ...]
    context_hash: str
    source_revision: str | None
    environment: str | None
    prompt_version: str
    prompt_hash: str
    provider: str
    model: str
    schema_version: str = SCHEMA_VERSION
    policy_version: str = POLICY_VERSION

    def compute_key(self) -> str:
        """Compute canonical SHA-256 cache key across all security and version dimensions."""
        return sha256_canonical(
            {
                "task_type": self.task_type.value,
                "incident_id": self.incident_id,
                "authorization_scope": self.authorization_scope,
                "finding_hash": self.finding_hash,
                "evidence_hashes": sorted(self.evidence_hashes),
                "context_hash": self.context_hash,
                "source_revision": self.source_revision,
                "environment": self.environment,
                "prompt_version": self.prompt_version,
                "prompt_hash": self.prompt_hash,
                "provider": self.provider,
                "model": self.model,
                "schema_version": self.schema_version,
                "policy_version": self.policy_version,
            }
        )


@dataclass
class _CacheEntry:
    value: Any
    cached_at: datetime
    expires_at: datetime
    authorization_scope: str
    incident_id: str


class SafeAIResultCache:
    """Bounded LRU + TTL in-memory cache (never persists credentials or invalid outputs)."""

    def __init__(self, *, max_entries: int = 128, ttl_seconds: int = 300) -> None:
        self._max_entries = max(1, max_entries)
        self._ttl_seconds = max(1, ttl_seconds)
        self._store: OrderedDict[str, _CacheEntry] = OrderedDict()

    def get(
        self,
        key_input: CacheKeyInput,
        *,
        now: datetime,
    ) -> Any | None:
        """Retrieve a validated entry iff key, authorization scope, and TTL all match."""
        key = key_input.compute_key()
        entry = self._store.get(key)
        if entry is None:
            return None
        if entry.incident_id != key_input.incident_id:
            return None
        if entry.authorization_scope != key_input.authorization_scope:
            return None
        if now >= entry.expires_at:
            self._store.pop(key, None)
            return None
        self._store.move_to_end(key)
        return entry.value

    def put(
        self,
        key_input: CacheKeyInput,
        value: Any,
        *,
        now: datetime,
        is_valid_result: bool = True,
    ) -> None:
        """Cache a validated result; refuses unvalidated/failed outcomes."""
        if not is_valid_result:
            return
        key = key_input.compute_key()
        self._store[key] = _CacheEntry(
            value=value,
            cached_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
            authorization_scope=key_input.authorization_scope,
            incident_id=key_input.incident_id,
        )
        self._store.move_to_end(key)
        while len(self._store) > self._max_entries:
            self._store.popitem(last=False)

    def invalidate_incident(self, incident_id: str) -> int:
        """Remove all cached results associated with ``incident_id``."""
        keys = [k for k, v in self._store.items() if v.incident_id == incident_id]
        for k in keys:
            self._store.pop(k, None)
        return len(keys)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
