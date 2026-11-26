# Killswitch X — Security Model & Threat Analysis

## 1. Scope & Authorization Principle

All security testing, vulnerability reproduction, feature-flag containment, and candidate patch verification in Killswitch X MUST operate exclusively against owned, authorized demonstration environments. Phase 02 adds deterministic state-machine guards, producer authentication checks, live-vs-fixture provenance enforcement, single-use approval binding, optimistic concurrency, and side-effect-free replay; no live scanning, exploit testing, Flagsmith mutation, or patch execution occurs yet.

## 2. Threat Model & Mitigations

| Threat | Impact | Implemented Phase 01 Control | Deferred Platform/Runtime Control |
| :--- | :--- | :--- | :--- |
| **LLM Hallucinations** | Invented flags, fabricated pass results, false root causes | Strict Pydantic validation (`extra="forbid"`), `EvidenceProvenance`, `OperationReceipt` rejects `llm_interpretation` | Deterministic policy engine & cross-checking against `FeatureStateReader` |
| **Prompt Injection in Findings** | Malicious scanner payload hijacks reasoning or suggests disabling unrelated flags | `LLMRequest` separates `system_prompt` from bounded `user_context`; `ContainmentProposal` validated against declared `RouteFlagRegistry` | Context delimiter hardening & output policy verification in `agent_core` |
| **Untrusted Repository Content** | Malicious code comments inject instructions into patch generator | `PatchProposal` enforces relative POSIX path safety and `touched_files` subset of `allowed_files` | AST/diff sanitization and isolated container execution in `security` |
| **Fabricated Evidence** | Unverified findings or empty logs treated as verified containment | `Finding(status="reproduced")` requires non-empty `evidence_ids`; `ArtifactReference` enforces 64-hex SHA-256; `EvidenceReport` forbids `complete` when `missing_evidence` is non-empty | `EvidenceRepository.artifact_exists(id, incident_id=...)` verification |
| **Unauthorized Feature Changes** | AI directly toggles Flagsmith flags | `FeatureStateReader` has zero mutation methods; `AIServiceSettings` excludes `flagsmith_management_token`; `ContainmentProposal.approval_required` must be `True` | Authenticated RBAC & Flagsmith management execution exclusively in `platform` |
| **Stale Approvals** | Old approval reused after expiration or proposal edit | `validate_approval_for_proposal` enforces `expires_at > now`, `proposal_hash`, `proposal_id`, `incident_id` | Transactional approval invalidation on state/revision change |
| **Duplicate Operations** | Retries double-toggle flags or replay events | Unique `idempotency_token` / `nonce` / `idempotency_key` fields | Database unique constraints & idempotency ledger |
| **Invalid Feature Mappings** | Wrong flag disabled or ambiguous match auto-selected | `MappingResult` forbids `selected_flag` when `ambiguous`/`unmapped` and enforces `manual_review_required=True` | Deterministic registry check & unknown-flag rejection (`UnknownFeatureError`) |
| **Candidate Patch Path Violations** | Patch modifies `.env`, auth middleware, or traverses `../` | `validate_relative_safe_path` & `validate_touched_files_within_allowlist` reject `..`, `/`, `\`, and non-allowlisted paths | Read-only filesystem & chroot/container isolation in `PatchTestRunner` |
| **Test-Result Manipulation** | Security test pass hides broken functionality or stale commit | `PatchTestResult` forbids `test_passed` if any `IndividualTestOutcome` failed/errored; `is_trusted_pass` checks `tested_source_revision == expected_source_revision` | Signed/hashed isolated runner logs in `EvidenceRepository` |
| **Unsafe Recovery Recommendations** | Rollback re-enables vulnerable legacy implementation | `RollbackProposal` enforces `approval_required=True`, separates `last_verified_safe_state_known`, and mandates `manual_review_required=True` when unknown | Human operator sign-off in `platform` |
| **Secret Leakage** | API keys, bearer tokens, or Flagsmith tokens logged or surfaced in errors | `SecretStr` in settings, `safe_summary()` masking, `_sanitize_context()` in `KillswitchError`, `redact_text`/`redact_mapping` in `logging_config.py` | CI secret scanning & runtime vault injection |
| **Unverified Deployment Information** | Flag enabled before fixed code is deployed | `DeploymentEvidence` distinguishes `observed` from `missing`/`unknown` and blocks `addressable=True` unless `observed` | Live deployment manifest verification in `DeploymentStateReader` |
| **Incorrectly Trusted Synthetic Telemetry** | Demo metrics mistaken for production health | `MetricSnapshot.provenance` explicitly marks `synthetic_telemetry`; `RolloutPolicyConfig.is_demo_default=True` | UI badges and production telemetry adapter differentiation |

## 3. Mandatory Controls Checklist

1. **Human approval for every privileged change** (`approval_required=True` enforced by schemas).
2. **Deterministic authorization checks** (`validate_approval_for_proposal` + `platform` session check).
3. **Environment and feature allowlists** (`RouteFlagRegistry.declared_features`).
4. **Exact proposal identity** (`CANONICAL_PROPOSAL_HASH_FIELDS` SHA-256 digest).
5. **Evidence provenance** (`EvidenceProvenance` enum on findings, receipts, telemetry, artifacts).
6. **Bounded LLM context** (`LLMRequest.max_context_chars` & `AIServiceSettings.llm_max_context_chars`).
7. **Structured model output validation** (`extra="forbid"`, `StrictBool`, `StrictInt`, UTC enforcement).
8. **Isolated test execution** (`PatchTestRunner` & `SecurityVerifier` protocols with zero shell APIs).
9. **Explicit failure states** (`FeatureObservationStatus.UNKNOWN`, `TestExecutionStatus.INFRASTRUCTURE_ERROR`, `RolloutDecisionType.HOLD`).
10. **Artifact integrity references** (`ArtifactReference` SHA-256 verification).
11. **Safe fallback behavior** (fail closed on missing data, expired approvals, or unavailable services).
