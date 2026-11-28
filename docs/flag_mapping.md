# Phase 04 — Deterministic Vulnerability-to-Feature-Flag Mapping

## 1. Architecture Overview

`DeterministicFlagMapper` (`agent_core/flag_mapper.py`) implements `FeatureMapperAgent` with zero LLM calls, zero privileged Flagsmith mutations, and zero mutation of input objects.

Pipeline:
1. **Registry Validation & Indexing** (`agent_core/mapping/registry.py`): Validates `RouteFlagRegistry` schema version, content SHA-256 fingerprint, environment, revision binding, unique routes, non-conflicting aliases/variants, declared feature membership, and role consistency.
2. **Evidence & Provenance Gate** (`agent_core/mapping/evidence_validator.py`): Rejects `suspected` findings from actionable progression, enforces artifact existence and incident/revision binding in live mode, and isolates `reference_fixture` provenance from live operations.
3. **Route, Component & Implementation Resolution** (`agent_core/mapping/resolvers.py`): Exact canonical route, explicit alias, and declared variant matching (no fuzzy/substring/prefix guessing); component and explicit component-alias resolution with route-component conflict detection; trusted implementation binding resolution (`observed_implementation`, `VerificationResult`, `registered_test_id`, or single binding).
4. **Runtime Feature-State Validation** (`agent_core/mapping/state_validator.py`): Injectable clock and configurable `FreshnessPolicy` (default `max_age_seconds=300`, `max_future_skew_seconds=30` — configurable engineering policy, not an empirical security guarantee). Distinguishes `observed` (enabled/disabled), `unknown`, `unavailable`, `stale`, `conflicting`, and segment-targeting uncertainty.
5. **6-Tier Deterministic Decision Policy** (`agent_core/mapping/decision_policy.py`): Order-invariant candidate discovery separating structural mapping (`MappingStatus`) from operational readiness (`MappingActionEligibility`: `eligible`, `hold`, `blocked`).
6. **Independent Policy & Guard Validation** (`agent_core/policies.py`, `agent_core/guards.py`): Recomputes authoritative candidates via `compute_authoritative_candidates` so an injected or buggy mapper cannot map `/search` to `files_v1` even though `files_v1` is globally declared.
7. **Orchestrator Integration** (`agent_core/orchestrator.py`): `IncidentOrchestrator.execute_mapping` records `MAPPING_REQUESTED`, persists mapping diagnostics, and dispatches `MAPPING_MATCHED` (-> `FLAG_MAPPED`), `MAPPING_AMBIGUOUS`, `MAPPING_UNMAPPED`, or `MAPPING_FAILED` (-> `UNMAPPED`) with `MANUAL_REVIEW_REQUESTED` when required.

## 2. Dashboard Serialization & Phase 05/06 Readiness

`serialize_mapping_dashboard(outcome)` (`agent_core/mapping/dashboard.py`) produces deterministic JSON containing `mapping`, `validation`, `feature_observation`, `operational_readiness`, `phase_05_context` (`affected_routes`, `shared_feature_dependencies`, `potential_replacements`, `fallback_behavior`), `provenance`, `is_fixture_only`, `missing_evidence`, `limitations`, and `reason_codes`.

## 3. Cybersecurity Branch Compatibility & Schema Reconciliation

`agent_core/adapters/security_contract.py` normalizes `feat/security` payloads (`sqli` -> `sql_injection`, `before` -> `before_containment`, `infrastructure_error` with `passed=False` -> `TestExecutionStatus.INFRASTRUCTURE_ERROR` with `passed=None`, `contained_smoke_failed` -> `passed=False`, `revision`/`requested_revision` -> `tested_revision`/`expected_revision`).

### Proposed Cross-Lane Schema Reconciliation
- Preserve `shared/schemas.py` on `Feature` as the canonical superset.
- Have `security/models.py` continue subclassing `Finding` and `VerificationResult` while adopting `VerificationPhase` (`before_containment`) and `TestExecutionStatus.INFRASTRUCTURE_ERROR` (`passed=None`), or route through `security_contract.py` at the platform API boundary.
- Platform lane (`platform/`) will eventually supply authoritative deployed `RouteFlagRegistry` declarations and `FeatureStateReader` snapshots.

## 4. Verification Commands

```bash
.venv/bin/python -m agent_core.demos.mapping_demos
.venv/bin/python -m agent_core.evaluations.mapping_evaluator
.venv/bin/pytest -v
```
