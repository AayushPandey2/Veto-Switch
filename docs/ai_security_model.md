# Killswitch X — AI Security Model & Threat Boundaries

## 1. Threat Model & Trust Boundaries
Untrusted content processed by the Investigator includes source-code comments, scanner descriptions, application logs, dependency advisories, artifact text, and tool outputs. Killswitch X assumes adversarial prompt injections WILL appear in untrusted inputs and treats prompt instructions as defense-in-depth rather than an authorization mechanism.

## 2. Implemented Protections
- **Credential & Privilege Isolation**: `AIServiceSettings` (`shared/config.py`) excludes all `PlatformPrivilegedSettings` fields (DB URLs, Flagsmith management tokens, approval signing secrets). `GatewayLLMRequest` rejects secret keys and Bearer/API-key patterns. Observability logs exclude raw prompts and source code by default.
- **Strict Read-Only Tool Policy (`agent_core/tools/`)**: `ToolRegistry` permits `side_effect="read_only"` only and blocks shell/mutation/secret/deploy/approval tool names. `ToolPolicyEnforcer` verifies incident scoping, relative safe paths, per-call and cumulative byte limits, duplicate call caps, and call/round limits outside the model.
- **Instruction / Data Separation**: Untrusted JSON context is placed strictly inside user-message delimiters (`<<<BEGIN_UNTRUSTED_EVIDENCE_DATA>>>`), never system instructions.
- **Output & Status Invariants**: `RawInvestigationOutput` enforces `extra="forbid"`, strict types, allowed next-action enums, and qualitative confidence. `InvestigationResponseValidator` and `policies.validate_investigation_output` block promoting `suspected` -> `reproduced` or claiming unverified deployments/approvals.
- **Deterministic State-Machine Guardrails**: `IncidentOrchestrator` prohibits `INVESTIGATION_COMPLETED` from transitioning `RECEIVED -> REPRODUCED`, `REPRODUCED -> FLAG_MAPPED`, `AWAITING_APPROVAL -> APPLYING`, `CONTAINED`, or `RECOVERED`.
- **Failover Data Sensitivity**: `ModelRouter` forbids silent failover for `SENSITIVE_SOURCE` or `RESTRICTED_SECURITY` data unless explicitly allowed by target configuration.

## 3. Partial Protections vs Deferred Platform Integration
- **Implemented & Verified Offline**: Tool allowlisting, incident/path scoping, structured schema validation, reference grounding, contradiction heuristics, status preservation, secret redaction, and orchestrator guard enforcement.
- **Partial (Heuristic Scope)**: Open-ended technical prose paraphrasing false root causes cannot be universally detected without semantic/human review (`semantic_review_required=True`).
- **Requires Future Platform Layers**: Persistent tamper-evident database event storage (`platform/`), mTLS producer authentication, and isolated Flagsmith execution remain outside Phase 03 scope.
