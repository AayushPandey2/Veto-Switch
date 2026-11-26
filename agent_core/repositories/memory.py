"""Thread/async-safe in-memory reference repository for orchestration & testing.

IMPORTANT LIMITATION:
    This repository stores all state in process memory and is NOT durable across
    restarts or multiple worker processes. Production deployments MUST use the
    transactional durable repository owned by the platform engineer (enforcing
    database transactions, unique constraints on ``event_id`` and
    ``idempotency_key``, and optimistic compare-and-set on ``incident_version``).
"""

from __future__ import annotations

import asyncio

from shared.contracts import EvidenceRepository
from shared.exceptions import (
    ArtifactValidationError,
    ConcurrencyConflictError,
    IdempotencyConflictError,
    InvalidTransitionError,
)
from shared.schemas import ArtifactReference, ContainmentProposal, IncidentEvent
from shared.serialization import sha256_bytes

from agent_core.context import DownstreamRequest, EventProcessingResult, OrchestrationRepository
from agent_core.idempotency import compute_event_payload_hash
from agent_core.incident import IncidentAggregate


class InMemoryOrchestrationRepository(OrchestrationRepository, EvidenceRepository):
    """Atomic in-memory reference repository implementing orchestration & evidence contracts."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._incidents: dict[str, IncidentAggregate] = {}
        self._events_by_incident: dict[str, list[IncidentEvent]] = {}
        self._events_by_id: dict[str, IncidentEvent] = {}
        self._event_hashes: dict[str, str] = {}
        self._processed_results: dict[str, EventProcessingResult] = {}
        self._proposals_by_id: dict[str, ContainmentProposal] = {}
        self._operations_by_idempotency: dict[str, DownstreamRequest] = {}
        self._artifacts: dict[str, ArtifactReference] = {}
        self._artifact_bytes: dict[str, bytes] = {}
        self._pending_requests: list[DownstreamRequest] = []

    async def create_incident(
        self,
        incident: IncidentAggregate,
        initial_event: IncidentEvent,
        initial_result: EventProcessingResult,
    ) -> IncidentAggregate:
        async with self._lock:
            if incident.incident_id in self._incidents:
                raise ConcurrencyConflictError(
                    f"Incident {incident.incident_id!r} already exists.",
                    context={"incident_id": incident.incident_id},
                )
            if initial_event.event_id in self._events_by_id:
                raise IdempotencyConflictError(
                    f"Initial event {initial_event.event_id!r} already exists.",
                    context={"event_id": initial_event.event_id},
                )
            self._incidents[incident.incident_id] = incident
            self._events_by_incident[incident.incident_id] = [initial_event]
            self._events_by_id[initial_event.event_id] = initial_event
            self._event_hashes[initial_event.event_id] = compute_event_payload_hash(initial_event)
            self._processed_results[initial_event.event_id] = initial_result
            return incident

    async def get_incident(self, incident_id: str) -> IncidentAggregate | None:
        async with self._lock:
            return self._incidents.get(incident_id)

    async def get_incident_version(self, incident_id: str) -> int | None:
        async with self._lock:
            inc = self._incidents.get(incident_id)
            return inc.incident_version if inc is not None else None

    async def append_incident_event(self, event: IncidentEvent) -> IncidentEvent:
        async with self._lock:
            if event.event_id in self._events_by_id:
                raise IdempotencyConflictError(
                    f"Duplicate event_id {event.event_id!r}.",
                    context={"event_id": event.event_id},
                )
            self._events_by_id[event.event_id] = event
            self._event_hashes[event.event_id] = compute_event_payload_hash(event)
            self._events_by_incident.setdefault(event.incident_id, []).append(event)
            return event

    async def list_incident_events(self, incident_id: str) -> list[IncidentEvent]:
        async with self._lock:
            events = self._events_by_incident.get(incident_id, [])
            return sorted(events, key=lambda evt: evt.sequence_number)

    async def get_event_by_id(self, event_id: str) -> IncidentEvent | None:
        async with self._lock:
            return self._events_by_id.get(event_id)

    async def get_processed_result(self, event_id: str) -> EventProcessingResult | None:
        async with self._lock:
            return self._processed_results.get(event_id)

    async def save_proposal(self, proposal: ContainmentProposal) -> None:
        async with self._lock:
            self._proposals_by_id[proposal.proposal_id] = proposal

    async def get_active_proposal(self, incident_id: str) -> ContainmentProposal | None:
        async with self._lock:
            inc = self._incidents.get(incident_id)
            if inc is None or inc.current_proposal_id is None:
                return None
            return self._proposals_by_id.get(inc.current_proposal_id)

    async def get_operation_by_idempotency_key(
        self, idempotency_key: str
    ) -> DownstreamRequest | None:
        async with self._lock:
            return self._operations_by_idempotency.get(idempotency_key)

    async def list_pending_requests(
        self, incident_id: str | None = None
    ) -> list[DownstreamRequest]:
        async with self._lock:
            if incident_id is None:
                return list(self._pending_requests)
            return [r for r in self._pending_requests if r.incident_id == incident_id]

    async def commit_transition(
        self,
        *,
        expected_version: int,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        result: EventProcessingResult,
        proposal: ContainmentProposal | None = None,
        reserved_request: DownstreamRequest | None = None,
    ) -> IncidentAggregate:
        """Atomically commit incident state, event, proposal, and operation reservation."""
        async with self._lock:
            current = self._incidents.get(updated_incident.incident_id)
            if current is None:
                raise InvalidTransitionError(
                    f"Incident {updated_incident.incident_id!r} does not exist.",
                    context={"incident_id": updated_incident.incident_id},
                )
            if current.incident_version != expected_version:
                raise ConcurrencyConflictError(
                    f"Optimistic concurrency conflict on incident {current.incident_id!r}: "
                    f"expected version {expected_version}, found {current.incident_version}.",
                    context={
                        "incident_id": current.incident_id,
                        "expected_version": expected_version,
                        "actual_version": current.incident_version,
                    },
                )

            if event.event_id in self._events_by_id:
                existing_hash = self._event_hashes[event.event_id]
                if existing_hash != compute_event_payload_hash(event):
                    raise IdempotencyConflictError(
                        f"Conflicting duplicate event_id {event.event_id!r}.",
                        context={"event_id": event.event_id},
                    )
                return current

            if reserved_request is not None and reserved_request.idempotency_key:
                existing_op = self._operations_by_idempotency.get(reserved_request.idempotency_key)
                if existing_op is not None:
                    raise IdempotencyConflictError(
                        "Logical operation already reserved for idempotency_key.",
                        context={"idempotency_key": reserved_request.idempotency_key},
                    )

            if proposal is not None:
                self._proposals_by_id[proposal.proposal_id] = proposal

            if reserved_request is not None:
                if reserved_request.idempotency_key:
                    self._operations_by_idempotency[reserved_request.idempotency_key] = (
                        reserved_request
                    )
                self._pending_requests.append(reserved_request)
            elif result.pending_requests:
                self._pending_requests.extend(result.pending_requests)

            self._events_by_id[event.event_id] = event
            self._event_hashes[event.event_id] = compute_event_payload_hash(event)
            self._events_by_incident.setdefault(event.incident_id, []).append(event)
            self._processed_results[event.event_id] = result
            self._incidents[updated_incident.incident_id] = updated_incident
            return updated_incident

    # --- EvidenceRepository methods ---
    async def store_artifact(
        self, reference: ArtifactReference, content: bytes
    ) -> ArtifactReference:
        if sha256_bytes(content) != reference.content_hash:
            raise ArtifactValidationError(
                "Artifact bytes do not match ArtifactReference content_hash.",
                context={"artifact_id": reference.artifact_id},
            )
        async with self._lock:
            self._artifacts[reference.artifact_id] = reference
            self._artifact_bytes[reference.artifact_id] = content
            return reference

    async def get_artifact_reference(self, artifact_id: str) -> ArtifactReference | None:
        async with self._lock:
            return self._artifacts.get(artifact_id)

    async def artifact_exists(self, artifact_id: str, *, incident_id: str) -> bool:
        async with self._lock:
            ref = self._artifacts.get(artifact_id)
            return ref is not None and ref.incident_id == incident_id

    async def list_incident_artifacts(self, incident_id: str) -> list[ArtifactReference]:
        async with self._lock:
            return [ref for ref in self._artifacts.values() if ref.incident_id == incident_id]
