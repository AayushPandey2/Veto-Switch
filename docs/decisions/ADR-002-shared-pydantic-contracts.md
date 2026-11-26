# ADR-002: Shared Pydantic Contracts

## Context
Four engineers work in parallel across `agent_core/`, `remediation/`, `security/`, and `platform/`. Unstructured dictionaries across subsystem boundaries invite subtle schema drift and silent coercion bugs.

## Decision
Centralize all cross-team data models in `shared/schemas.py` using Pydantic v2 (`KillswitchModel` with `extra="forbid"`, `StrictBool`, `StrictInt`, and UTC-aware `UtcDatetime`), backed by `StrEnum` in `shared/enums.py`.

## Alternatives
1. Plain Python `dataclasses` or `TypedDict`s without runtime validation.
2. Per-subsystem duplicate schemas with manual adapters.

## Rationale
Pydantic v2 provides runtime validation, strict JSON serialization, mypy integration (`pydantic.mypy`), and immediate detection of invalid AI outputs or malformed integration payloads.

## Consequences
- Subsystems share one canonical schema contract (`shared`).
- Contract changes must remain backwards-compatible or coordinated across teams.

## Known Limitations
Local Pydantic validation cannot verify cross-service facts (such as whether an `evidence_id` exists in persistent storage); repositories must enforce those checks.
