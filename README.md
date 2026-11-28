# Killswitch X (Veto-Switch)

> [!NOTE]
> **Status: Project is currently being built (Phases 01–05, 07, and 08 of 12 implemented; Phase 06 & Phases 09–12 under active development).**

**AI-assisted, evidence-driven cybersecurity incident containment, remediation, and recovery platform.**

Killswitch X receives vulnerability findings from authorized security testing systems, investigates impact and blast radius, maps vulnerable components to Flagsmith feature flags, proposes least-disruptive containment requiring explicit human approval, verifies containment via security regression tests, validates candidate code patches in isolated runners, plans progressive recovery rollouts, and exports complete incident evidence bundles.

## What Is Built So Far

- **Phase 01 — Project Foundation & Shared Contracts (`shared/`, `config/`, `tests/`):** Strict Pydantic v2 schemas, centralized `StrEnum`s, service protocols (`FeatureStateReader` strictly read-only, `LLMProvider`, `PatchTestRunner`), trust-separated settings (`AIServiceSettings` vs `PlatformPrivilegedSettings`), secret redaction, SHA-256 artifact hashing, and fixture validation.
- **Phase 02 — Incident State Machine & Orchestration (`agent_core/`):** Deterministic finite-state machine, centralized transition & evidence registry, 20 fail-closed guards, `IncidentOrchestrator`, idempotency, optimistic concurrency, bounded retry policy, deterministic event replay, in-memory reference repository, and 8 synthetic simulations (`A–H`).
- **Phase 03 — AI Investigator & Provider-Independent LLM Infrastructure (`agent_core/`):** `LLMGateway`, `ProviderRegistry`, `FixtureLLMProvider` (`offline_fixture`), configurable `GeminiLLMProvider` (REST over `httpx`), model routing, token budgeting, versioned SHA-256-hashed `PromptRegistry`, strictly read-only bounded tool system, 10-stage `InvestigationContextBuilder`, claim-level evidence grounding & contradiction checks, qualitative uncertainty assessment, `DeterministicFallbackInvestigator`, `Investigator` + dashboard JSON serializer, orchestrator integration, 24-case synthetic evaluation suite, and offline demonstrations (`B–I`).
- **Phase 04 — Vulnerability-to-Feature-Flag Mapping (`agent_core/flag_mapper.py`, `agent_core/mapping/`):** Deterministic 6-tier flag mapping, registry SHA-256 validation, runtime feature state checks, 10 offline demos, and 12-case evaluator.
- **Phase 05 — Blast Radius Intelligence & Containment Strategist (`agent_core/blast_radius.py`, `agent_core/containment_strategist.py`):** Directed multigraph blast radius analysis, deterministic containment proposal generation (`AWAITING_APPROVAL`), 7-case evaluator, and offline demos.
- **Phase 07 — Evidence-Grounded AI Patch Engineer (`remediation/patch_agent.py`, `remediation/patching/`):** Target-scoped candidate patch generation (`stand_in` vs `platform_demo_app`), strict unified diff parsing, AST static safety & minimality checks, `ArtifactType.PATCH_DIFF` persistence, PR-ready review summaries, and 5-case evaluator.
- **Phase 08 — Isolated Patch Verification (`remediation/patch_tests.py`, `remediation/verification/`, `remediation/adapters/`):** Isolated verification orchestrator (`SecurityServicePatchRunner` + offline `FixturePatchTestRunner`), mandatory test-plan completeness, 5-point revision identity checks, sandbox isolation & evidence integrity gates, Phase 09 `RecoveryHandoff` (`deployment_verified=False`, `rollout_authorized=False`), Demos A–J, and 15-case evaluator.
- **In Progress (Phase 06 & Phases 09–12):** Feature flag coverage auditor, progressive rollout/rollback execution, Flagsmith management executor, FastAPI platform backend, and web UI.

## Technology Stack

- **Language:** Python 3.11+ (verified on Python 3.12)
- **Contracts & Settings:** Pydantic v2, Pydantic Settings, HTTPX
- **Quality & Testing:** Pytest, Pytest-Asyncio, Ruff, Mypy (`pydantic.mypy`)
- **Planned Integrations:** Flagsmith (via trusted platform layer), NetworkX, FastAPI, Uvicorn, Flask, React

## Quick Start & Verification (Offline)

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev]"

.venv/bin/python scripts/validate_fixtures.py
.venv/bin/ruff check .
.venv/bin/mypy shared agent_core remediation
.venv/bin/pytest -v
.venv/bin/python -m agent_core.simulations
.venv/bin/python -m agent_core.demos
.venv/bin/python -m agent_core.evaluations.regression
```

## Documentation

- [System Architecture](docs/architecture.md) & [AI Architecture](docs/ai_architecture.md)
- [Orchestration](docs/orchestration.md) & [State Machine](docs/state_machine.md)
- [LLM Integration](docs/llm_integration.md), [Context Engineering](docs/context_engineering.md), [Prompt Engineering](docs/prompt_engineering.md)
- [Evidence Grounding](docs/evidence_grounding.md), [AI Security Model](docs/ai_security_model.md), [AI Evaluation](docs/ai_evaluation.md)
- [Integration Contracts](docs/integration_contracts.md), [Patch Engineer](docs/patch_engineer.md), [Patch Verification](docs/patch_verification.md), & [Implementation Status](docs/implementation_status.md)
