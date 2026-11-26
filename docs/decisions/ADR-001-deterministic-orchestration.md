# ADR-001: Deterministic Orchestration Over Unrestricted Autonomous Agents

## Context
Killswitch X coordinates high-stakes cybersecurity containment, feature-flag changes, source patching, and progressive rollout decisions. Unrestricted autonomous agent loops risk hallucinated transitions, skipped approvals, or unsafe flag toggles.

## Decision
Use an explicit deterministic state machine (`IncidentState`) and deterministic policy evaluators to govern all state transitions, authorization gates, and rollout eligibility, while confining LLMs strictly to bounded investigation, explanation, and candidate patch drafting.

## Alternatives
1. Fully autonomous ReAct/tool-calling agent loop driving state transitions directly.
2. Purely static rule engine with zero AI assistance.

## Rationale
Deterministic control guarantees reproducible state transitions, fail-closed checks, and auditable approvals, while still capturing AI productivity for root-cause synthesis and patch drafting.

## Consequences
- Every transition can be validated and replayed deterministically from `IncidentEvent` logs.
- Phase 02 must implement explicit transition guards in `agent_core/orchestrator.py`.

## Known Limitations
Deterministic transition tables require deliberate extension whenever new incident stages or remediation strategies are introduced.
