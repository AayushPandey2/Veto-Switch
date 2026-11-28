# `agent_core/` — Agent Intelligence and Orchestration

**Owner:** AI/ML Engineer 1

## Responsibilities

- Deterministic incident state machine, transition registry, guards, orchestrator, idempotency, concurrency control, bounded retry, and replay (`orchestrator.py`, `state_machine.py`, `transitions.py`, `guards.py`, `incident.py`, `events.py`, `event_handlers.py`, `event_dispatcher.py`, `approval_validator.py`, `evidence_validator.py`, `idempotency.py`, `replay.py`, `retry_policy.py`, `policies.py`, `repositories/memory.py`) — **Implemented in Phase 02**
- Provider-independent LLM Gateway, provider registry, model routing, token budgeting, structured-output repair, caching, observability (`llm/`, `llm_client.py`) — **Implemented in Phase 03**
- Versioned Investigator prompts (`prompts/`) and strictly read-only bounded tool system (`tools/`) — **Implemented in Phase 03**
- 10-stage context engineering pipeline, claim-level evidence grounding, uncertainty assessment, deterministic fallback, and AI Security Investigator (`intelligence/`, `investigator.py`) — **Implemented in Phase 03**
- Synthetic AI evaluation suite (`evaluations/`) and runnable offline demonstrations (`demos/`) — **Implemented in Phase 03**
- Offline fixture adapters & synthetic simulations (`adapters/fixtures.py`, `simulations/`) — **Implemented in Phase 02**
- Vulnerability-to-feature-flag mapper (`flag_mapper.py` — deferred to Phase 04; protocol in `context.py`)
- Blast Radius Intelligence & dependency graph analysis (`blast_radius.py` — deferred)
- Feature flag coverage auditing (`flag_auditor.py` — deferred)

## Verification, Demos & Evaluation

```bash
# Run all unit, contract & integration tests
.venv/bin/pytest -v

# Run Phase 02 synthetic orchestration simulations (A-H)
.venv/bin/python -m agent_core.simulations

# Run Phase 03 offline AI Investigator demonstrations (B-I; skips live Demo A cleanly offline)
.venv/bin/python -m agent_core.demos

# Run Phase 03 offline AI evaluation regression suite (generates JSON + MD reports)
.venv/bin/python -m agent_core.evaluations.regression
```

## Phase 03 Status

AI Investigator, provider-independent `LLMGateway`, `GeminiLLMProvider` (REST over `httpx`), `FixtureLLMProvider`, versioned prompt registry, 10-stage context pipeline, claim-level grounding & contradiction validator, read-only tool policy, deterministic fallback, orchestrator investigation integration, evaluation suite, and offline tests are implemented and verified. See [`docs/ai_architecture.md`](../docs/ai_architecture.md) and [`docs/implementation_status.md`](../docs/implementation_status.md).
