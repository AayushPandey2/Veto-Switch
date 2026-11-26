# ADR-003: Provider-Independent LLM Interface

## Context
The platform may run offline with deterministic fixtures during testing/CI or integrate with different LLM providers in live environments.

## Decision
Define an abstract `@runtime_checkable` `LLMProvider` protocol in `shared/contracts.py` accepting bounded `LLMRequest` inputs and returning validated `BaseModel` outputs plus `ModelMetadata`.

## Alternatives
1. Importing a specific vendor SDK directly across `agent_core` and `remediation`.
2. Untyped raw-string completion wrappers.

## Rationale
Dependency inversion decouples domain logic from vendor APIs, keeps offline unit tests free of live credentials, and enforces schema validation at the provider boundary.

## Consequences
- Concrete LLM adapters can be swapped without modifying `agent_core` or `remediation` domain logic.
- Provider errors must raise `LLMProviderError`, `LLMTimeoutError`, or `LLMResponseValidationError` rather than returning fabricated results.

## Known Limitations
Prompt sizing and context truncation remain the caller's responsibility up to `AIServiceSettings.llm_max_context_chars`.
