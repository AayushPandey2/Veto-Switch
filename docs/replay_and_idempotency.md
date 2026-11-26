# Killswitch X — Replay, Persistence & Idempotency

## 1. Optimistic Concurrency & Incident Versioning

`IncidentAggregate` is frozen (`frozen=True`) and maintains a monotonic `incident_version` starting at `1`. State changes occur exclusively through `IncidentAggregate.with_transition()`, and persistence commits via `OrchestrationRepository.commit_transition(expected_version=..., ...)`.

If a concurrent writer commits first, `commit_transition` raises `ConcurrencyConflictError`, and `IncidentOrchestrator.process_event` returns `EventProcessingResult(accepted=False, reason_code="CONCURRENCY_CONFLICT", retryable=True)` without overwriting the newer state.

## 2. Event Ordering & Idempotency

- **Event identity (`event_id`):** Checked against `EventRepository` before transition evaluation. Identical redelivery returns the cached outcome with `duplicate=True` and `pending_requests=[]` without incrementing `incident_version`. Same `event_id` with modified canonical payload raises `IdempotencyConflictError`.
- **Logical operation identity (`idempotency_key`):** Computed deterministically via `build_operation_idempotency_key(...)` over incident, proposal, approval, environment, feature, desired state, operation kind, and stage ID.
- **Sequence & causality:** `validate_event_ordering_and_causality` enforces `event.sequence_number == incident.latest_event_sequence + 1`, matching `correlation_id`, and `causation_id` on approval/execution/containment events.

## 3. Deterministic Replay (`agent_core/replay.py`)

`replay_incident(events)`:
1. Validates non-empty stream, single `incident_id`, unique `event_id`s, monotonic `sequence_number` starting at `1`, and initial `FINDING_RECEIVED`.
2. Replays every accepted event through `get_target_state` and `apply_transition` using recorded timestamps (`FixedClock(evt.timestamp_utc)`) and replay metadata (`_replay_meta`), never re-evaluating expired historical approvals against current wall-clock time.
3. Performs **zero** LLM calls, **zero** Flagsmith mutations, **zero** security tests, and **zero** downstream notifications.

## 4. In-Memory Reference Repository vs. Durable Platform DB

[`agent_core/repositories/memory.py`](../agent_core/repositories/memory.py) uses an `asyncio.Lock` during `commit_transition` to guarantee single-process atomicity for tests and simulations. It is **not durable** across process restarts or multiple workers.

The production durable repository (owned by `platform/`) must provide:
- Single ACID transaction committing `incidents` row update + `events` insert + `operations` reservation + `approvals` consumption.
- `WHERE incident_id = :id AND version = :expected_version` compare-and-set check.
- `UNIQUE` constraints on `event_id`, `(incident_id, sequence_number)`, `idempotency_token`, and `operation_idempotency_key`.
- Crash-recovery reconciliation querying `Flagsmith` readback / executor status before re-issuing uncertain writes.
