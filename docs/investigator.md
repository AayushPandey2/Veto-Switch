# Killswitch X — AI Security Investigator

## 1. Overview
`Investigator` (`agent_core/investigator.py`) implements `agent_core.context.InvestigatorAgent` and executes a deterministic 12-step investigation pipeline:
1. Validate target `Finding` identity.
2. Establish incident-scoped trusted evidence inputs (`InvestigationInputBundle`).
3. Build bounded, redacted, hash-tracked `InvestigationContext` via `InvestigationContextBuilder`.
4. Select versioned prompts via `PromptRegistry`.
5. Invoke `LLMGateway.generate_structured(..., RawInvestigationOutput)` under token, retry, and tool caps.
6. Validate strict Pydantic schema, safety constraints, and claim-level grounding (`validate_investigation_grounding`).
7. Decompose completeness, reproduction status, missing evidence, and qualitative `EvidenceSupportLevel` (`evaluate_uncertainty`).
8. Route failures, missing credentials, budget exhaustion, or grounding failures to `DeterministicFallbackInvestigator` (when `fallback_enabled=True`).
9. Attach sanitized execution metadata (`prompt_version`, `prompt_hash`, `context_hash`, `fallback_used`, latency, tokens).
10. Return `InvestigationExecutionResult` and frontend-ready dashboard JSON (`to_dashboard_payload()`).

## 2. Category Support
- **`sql_injection`**: Inspects database component, query construction pattern, parameter binding, input handling, and reproduction evidence without claiming unverified broader compromise.
- **`path_traversal`**: Inspects file-serving component, path normalization, root bounds, and reproduction logs without claiming sensitive file exposure unless verified.
- **`dependency_cve`**: Distinguishes `Advisory match != Code reachable != Reproduced != Security impact confirmed`.
- **`other` / unknown**: Gracefully preserves facts/gaps and enforces `require_manual_review` rather than forcing unsupported categorization.

## 3. Frontend-Ready Dashboard Serializer (`to_dashboard_payload()`)
Returns structured JSON with `investigation`, `validation`, and `execution` sections carrying explicit presentation badges (`verified_fact`, `inferred_interpretation`, `potential_impact`, `verified_impact`, `fallback_response`, `unverified_claims_present`, `requires_manual_review`). Passing schema and reference checks alone never labels open-ended interpretations as verified facts.
