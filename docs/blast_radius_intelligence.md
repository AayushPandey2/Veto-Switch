# Phase 05 — Blast Radius Intelligence & Containment Strategist

## 1. Architecture Overview

Phase 05 implements deterministic dependency graph analysis, counterfactual simulation, hard feasibility gates, multi-criteria policy ranking, and human-approval-ready proposal construction with zero LLM calls and zero privileged Flagsmith access.

Pipeline:
1. **Graph Validation & Indexing** (`agent_core/graph_intelligence/engine.py`): `validate_graph` checks node/edge integrity, endpoint types, size bounds, and environment/registry consistency. `DirectedMultiGraphIndex` builds O(V + E) forward/reverse adjacency lists preserving multiple relationship types between nodes.
2. **Relationship-Specific Blast Radius** (`agent_core/blast_radius.py`): `analyze_blast_radius` runs bounded O(V + E) BFS distinguishing:
   - `calls` / `depends_on`: affected routes and services vs preserved unrelated capabilities.
   - `controlled_by`: feature-flag control nodes.
   - `accesses`: shared databases/storage (exposed resources, NOT automatically marked unavailable).
   - `replaced_by`: candidate replacement implementations (not assumed deployed/verified).
   - `known_security_entry_points`: includes declared aliases and variants from `RouteFlagRegistry` (e.g., `/search`, `/legacy/search`, `/search/`).
3. **Counterfactual Simulation** (`agent_core/graph_intelligence/counterfactual.py`): Non-mutating hypothetical evaluation comparing `state_before` vs `hypothetical_state_after` with explicit qualifiers (`predicted`, `requires_verification`, `unknown`).
4. **Candidate Generation, Feasibility Gates & Scoring** (`agent_core/containment/engine.py`, `config/containment_policy.json`):
   - Evaluates disabling the mapped flag, switching to a replacement, and broad shutdown (manual-only comparison).
   - Hard feasibility gates precede scoring: unverified/suspected findings, ambiguous/unmapped/ineligible mappings, stale/missing feature states, already-disabled flags (recommend verification), missing fallback, and unverified/un-deployed/multi-flag replacements are blocked from becoming executable proposals.
   - Policy weights (configurable defaults in `config/containment_policy.json`, not empirical probabilities): `residual_exposure=0.50`, `operational_disruption=0.25`, `dependency_impact=0.15`, `uncertainty=0.10`.
   - Sensitivity analysis evaluates stability across `balanced`, `security_first`, and `availability_sensitive` profiles.
5. **Proposal Integrity Hardening (`v2`)** (`shared/schemas.py`, `agent_core/policies.py`): `ContainmentProposal` supports `hash_version="v2"`, binding `reason`, `expected_disruption`, `alternatives`, `evidence_ids`, `created_at`, `expires_at`, `rollback_considerations`, and `review_metadata`.
6. **Orchestrator Integration** (`agent_core/orchestrator.py`): `IncidentOrchestrator.execute_containment_analysis` transitions `FLAG_MAPPED -> CONTAINMENT_PROPOSED -> AWAITING_APPROVAL` (or emits `MANUAL_REVIEW_REQUESTED` when no safe executable strategy exists) and stops at the human-approval boundary.

## 2. Phase 06 Handoff

`DirectedMultiGraphIndex`, `BlastRadiusResult`, `serialize_blast_radius_dashboard`, and `RouteFlagRegistry` expose route-to-feature associations, alias entry points, shared implementations, and missing relationships for the Phase 06 Flag Coverage Auditor.

## 3. Verification Commands

```bash
.venv/bin/python -m agent_core.demos.blast_radius_demos
.venv/bin/python -m agent_core.evaluations.blast_radius_evaluator
.venv/bin/pytest -v
```
