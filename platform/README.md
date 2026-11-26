# `platform/` — Platform, API, Persistence, Approval & Flagsmith Execution

**Owner:** Full-stack and Cybersecurity Engineer

> [!CAUTION]
> **Python Standard Library Naming Rule:**
> Never create `__init__.py` directly inside `platform/` (nor add `platform/` as a top-level importable Python package in `pyproject.toml`). Doing so would shadow Python's built-in `platform` standard-library module (used by `pydantic`, `pytest`, `httpx`, and stdlib tooling).
> Future Python services under this directory should live in a distinct package namespace such as `platform/killswitch_platform/` or `platform/backend/app/`.

## Responsibilities

- FastAPI backend API & incident orchestration endpoints
- Flask vulnerable demonstration application (authorized target)
- React operator dashboard
- Database persistence (`IncidentRepository`, `EventRepository`, `EvidenceRepository`)
- Authenticated human approval system (`ApprovalReader` + cryptographic/session validation)
- Actual Flagsmith integration (`FeatureStateReader` read-only implementation + privileged executor)
- Authorized feature flag executor producing `shared.schemas.OperationReceipt`
- Telemetry collection (`TelemetryReader`) & deployment observation (`DeploymentStateReader`)

## Phase 01 Status

Ownership boundary, privileged settings separation (`shared.config.PlatformPrivilegedSettings`), and integration contracts are established. Platform implementation is intentionally deferred.
