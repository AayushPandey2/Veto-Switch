# Phase 06: Feature Flag Coverage Auditing

## Overview
`agent_core/flag_auditor.py` and `agent_core/coverage/` implement deterministic, read-only static control-flow and guard-dominance analysis for Flask route handlers. Zero LLM calls are required for authoritative coverage classifications, and analyzed source code is never executed or imported.

## Architecture
1. **Authorized Source Snapshot (`source_snapshot.py`)**: Enforces explicit file allowlists, rejects path traversal (`..`), absolute paths, escaping symlinks, unsupported extensions, and oversized files/ASTs. Computes SHA-256 per-file hashes and `source_tree_fingerprint`.
2. **Static Route Discovery (`route_discovery.py`)**: Extracts `@app.get`, `@app.post`, `@app.route`, and blueprint equivalents, flagging dynamic routes (`DYNAMIC_ROUTE_UNRESOLVED`) and separating intentional operational exemptions (`/health`, `/status`, `/manifest`, `/catalog`).
3. **Sensitive Implementation Index (`sensitive_paths.py`)**: Maps known sensitive sinks and bounded local helper calls up to `max_call_depth`.
4. **Boolean Guard & Control-Flow Analysis (`guard_analysis.py`, `control_flow.py`)**: Evaluates 3-valued `FeatureState` (`ENABLED`, `DISABLED`, `UNKNOWN`) truth tables over `provider.is_enabled(...)` and `provider.get_states(..., identity=...)` early-return and precedence guards. Detects logging-only checks, post-sink guards, wrong-flag checks, and insufficient `OR` expressions.
5. **Aggregation, Reconciliation & Runtime Corroboration (`classification.py`, `reconciliation.py`, `runtime_evidence.py`)**: Aggregates per-route and implementation-wide coverage (`protected`, `partially_protected`, `unprotected`, `unknown`), reconciles against `RouteFlagRegistry`, `DependencyGraph`, and manifests, and corroborates against trusted `FeatureState` / `VerificationResult` records.
6. **Dashboard & Endpoint Compatibility (`dashboard.py`)**: Exposes `serialize_coverage_dashboard` and `serialize_flags_coverage_endpoint` (preserving `covered` / `missing` / `status` while adding genuine static `coverage_status` and `applicability`).

## Commands
```bash
.venv/bin/python -m agent_core.demos.coverage_demos
.venv/bin/python -m agent_core.evaluations.coverage_evaluator
.venv/bin/pytest -q agent_core/tests/test_flag_auditor.py
```

## Phase 12 Integration Handoff
- Wire `platform/backend/app.py` `GET /flags/coverage` to `serialize_flags_coverage_endpoint` once `feat/platform` and `feat/security` are integrated in Phase 12.
- Live platform/security runtime corroboration remains blocked on `Feature` until cross-branch integration in Phase 12.
