"""Immutable, indexed storage for VerifiedSafeState checkpoints."""

from __future__ import annotations

from shared.schemas import VerifiedSafeState


class SafeStateHistoryStore:
    """In-memory immutable, indexed store of VerifiedSafeState checkpoints.

    Historical checkpoints are never deleted or mutated in place; invalidation
    records are preserved alongside evidence for replay and Phase 11 reporting.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, VerifiedSafeState] = {}
        self._by_incident: dict[str, list[str]] = {}

    def record(self, checkpoint: VerifiedSafeState) -> VerifiedSafeState:
        """Persist a VerifiedSafeState checkpoint immutably."""
        if checkpoint.safe_state_id in self._by_id:
            existing = self._by_id[checkpoint.safe_state_id]
            if existing != checkpoint:
                raise ValueError(
                    f"VerifiedSafeState {checkpoint.safe_state_id!r} already exists "
                    "and is immutable."
                )
            return existing
        stored = checkpoint.model_copy(deep=True)
        self._by_id[stored.safe_state_id] = stored
        self._by_incident.setdefault(stored.incident_id, []).append(stored.safe_state_id)
        return stored

    def get(self, safe_state_id: str) -> VerifiedSafeState | None:
        """Return a deep copy of a checkpoint by ID, if present."""
        cp = self._by_id.get(safe_state_id)
        return cp.model_copy(deep=True) if cp is not None else None

    def list_for_incident(self, incident_id: str) -> list[VerifiedSafeState]:
        """Return all historical checkpoints for an incident in deterministic order."""
        ids = self._by_incident.get(incident_id, [])
        checkpoints = [self._by_id[cid].model_copy(deep=True) for cid in ids]
        checkpoints.sort(key=lambda c: (c.verified_at, c.safe_state_id))
        return checkpoints
