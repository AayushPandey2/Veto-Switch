# Killswitch X — AI Subsystem Architecture

## 1. Design Philosophy
Killswitch X follows a strict separation between **AI interpretation** and **deterministic operational authority**:
- The LLM interprets normalized findings and supplied evidence and recommends next workflow actions.
- The LLM NEVER transitions incident state directly, approves actions, selects feature flags authoritatively, executes shell commands, or mutates Flagsmith.
- Every model response undergoes deterministic schema validation, claim-level reference verification, factual consistency checks, and orchestrator guard enforcement.

## 2. Subsystem Components
- **Provider Abstraction (`agent_core/llm/provider.py`, `provider_registry.py`, `error_mapping.py`)**: Defines `GatewayLLMProvider`, `ProviderCapabilities`, normalized error categories (`AIProviderErrorCategory`), secret-free `GatewayLLMRequest`, and `GatewayLLMResponse` preserving unknown token usage as `None`.
- **Concrete Providers (`agent_core/llm/providers/`)**:
  - `FixtureLLMProvider` (`offline_fixture`): deterministic offline scripted adapter for unit tests, demos, and offline evaluations (`synthetic_origin=True`).
  - `GeminiLLMProvider` (`gemini`): configurable live REST adapter using `httpx.AsyncClient` against Gemini `:generateContent` and `:countTokens`.
- **Central LLM Gateway (`agent_core/llm/gateway.py`, `agent_core/llm_client.py`)**: Single entry point handling routing, prompt version loading, token budgeting, bounded transport retries (reusing `agent_core/retry_policy.py`), bounded output repair loops, bounded read-only tool auditing, safe in-memory caching, and sanitized observability. Reusable by future Engineer 2 tasks (e.g., `candidate_patch_generation`).
- **Versioned Prompt Registry (`agent_core/prompts/`)**: Stores system, task, repair prompts, and synthetic examples with dynamic SHA-256 content hashes.
- **10-Stage Context Engineering (`agent_core/intelligence/context_builder.py`, `context_selector.py`, `context_budget.py`)**: Collects, validates incident/environment/revision/provenance consistency, prioritizes evidence, redacts secrets/PII, deduplicates without merging conflicting tests, compacts deterministically, enforces token budgets, serializes cleanly, and computes canonical context hashes.
- **Claim Grounding & Uncertainty (`evidence_grounding.py`, `claim_validator.py`, `uncertainty.py`, `confidence.py`)**: Verifies evidence references, catches deterministically detectable contradictions and hallucinated identifiers, separates completeness/reproduction/interpretation, and assigns qualitative evidence support labels (`EvidenceSupportLevel`).
- **Deterministic Fallback (`agent_core/intelligence/fallback.py`)**: Produces transparent, category-specific `DETERMINISTIC_FALLBACK` summaries when providers fail, credentials are absent, or model outputs fail validation.
- **Investigator (`agent_core/investigator.py`)**: Implements the 12-step investigation workflow, satisfies `agent_core.context.InvestigatorAgent`, and emits frontend-ready dashboard payloads (`to_dashboard_payload()`).
- **Orchestrator Integration (`agent_core/orchestrator.py`)**: `IncidentOrchestrator.execute_investigation` records `INVESTIGATION_REQUESTED`, stores a redacted investigation artifact, and emits `INVESTIGATION_COMPLETED` / `INVESTIGATION_FAILED` / `MANUAL_REVIEW_REQUESTED` under deterministic state-machine guards.

## 3. Data Flow

```text
Finding + Artifacts + Verifications + Bounded Source
                      |
                      v
     [10-Stage InvestigationContextBuilder]
     (Validate -> Select -> Redact -> Budget -> Hash)
                      |
                      v
               [LLMGateway] <---> [PromptRegistry]
          /           |           \
    [ModelRouter]  [TokenBudget]  [BoundedToolExecutor]
          \           |           /
                      v
        [GeminiLLMProvider | FixtureLLMProvider]
                      |
                      v
       [Structured Output + Bounded Repair]
                      |
                      v
     [Claim Grounding + Factual Consistency + Uncertainty]
            /                         \
      (Valid)                    (Failed / Unavailable)
        /                               \
       v                                 v
[InvestigationSummary]     [DeterministicFallbackInvestigator]
        \                               /
         \                             /
          v                           v
 [IncidentOrchestrator.execute_investigation]
 (INVESTIGATION_COMPLETED / MANUAL_REVIEW_REQUESTED; zero guard bypass)
```
