# Killswitch X — Versioned Prompt Engineering

## 1. Prompt Registry (`agent_core/prompts/`)
Prompts are managed externally in versioned template files indexed by `agent_core/prompts/versions.json` and loaded through `PromptRegistry`:
- `investigator/system.md` (`investigator_v1`, `version="1.0.0"`): System instructions enforcing investigator identity, strict trust hierarchy, hard security prohibitions, evidence grounding rules, uncertainty rules, and prohibition on private chain-of-thought emission.
- `investigator/investigation.md`: Task instructions wrapping serialized `context_json` strictly inside explicit `<<<BEGIN_UNTRUSTED_EVIDENCE_DATA>>>` ... `<<<END_UNTRUSTED_EVIDENCE_DATA>>>` delimiters.
- `investigator/repair_output.md`: Bounded schema/validation repair template accepting sanitized validation error summaries only.
- `investigator/examples.json`: Explicitly labeled `synthetic_illustrative_examples` demonstrating SQLi and Dependency CVE structured JSON shapes.
- `candidate_patch_placeholder_v1`: Interface placeholder reserving `AITaskType.CANDIDATE_PATCH_GENERATION` for future Engineer 2 work.

## 2. Traceability & Security
- Every loaded prompt dynamically computes a SHA-256 `content_hash` over its templates so any silent edit invalidates historical hash equivalence.
- `PromptRegistry` forbids path traversal outside `agent_core/prompts/` and never interpolates untrusted evidence text into `system_instructions`.
- Exact `prompt_version` and `prompt_hash` are recorded on `ModelMetadata`, `AIExecutionRecord`, `InvestigationSummary`, and `EvaluationRunReport`.
