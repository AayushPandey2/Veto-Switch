# Killswitch X — Integration Contracts

This document specifies all cross-team service boundaries defined in [`shared/contracts.py`](../shared/contracts.py) and [`shared/schemas.py`](../shared/schemas.py).

## 1. Summary Matrix

| # | Interaction | Producer | Consumer | Input Model | Output Model | Approval Required | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Security → Agent Core | `security` | `agent_core` | Verification trigger | `Finding`, `VerificationResult` | No (read/verify only) | Contract, fixtures & orchestrator intake implemented |
| 2 | Platform → Agent Core | `platform` | `agent_core` | Env / Incident query | `RouteFlagRegistry`, `FeatureState`, `ApprovalDecision`, `OperationReceipt` | N/A (readback/receipt) | Contract, guards & validators implemented |
| 3 | Agent Core → Platform | `agent_core` | `platform` | Incident context | `InvestigationSummary`, `MappingResult`, `ContainmentProposal`, `DependencyGraph`, `CoverageFinding`, `IncidentEvent`, `DownstreamRequest` | Yes (for `ContainmentProposal`) | Orchestrator & `DownstreamRequest` emission implemented |
| 4 | Agent Core → Remediation | `agent_core` | `remediation` | Contained incident | `IncidentRecord`, `IncidentAggregate`, `Finding`, `VerificationResult` | No | Contract & state transitions implemented |
| 5 | Remediation → Security | `remediation` | `security` | `PatchProposal` | `test_run_id` (via `PatchTestRunner`) | No (isolated sandbox) | Contract & fixtures defined |
| 6 | Security → Remediation | `security` | `remediation` | `test_run_id` | `PatchTestResult`, `ArtifactReference` | No | Contract & fixtures defined |
| 7 | Platform → Remediation | `platform` | `remediation` | Env / Feature query | `DeploymentEvidence`, `FeatureState`, `MetricSnapshot`, `ApprovalDecision` | N/A | Contract & fixtures defined |
| 8 | Remediation → Platform | `remediation` | `platform` | Contained & tested context | `PatchProposal`, `PatchTestResult`, `RolloutPlan`, `RolloutDecision`, `RollbackProposal`, `EvidenceReport` | Yes (for rollout/rollback) | Contract & fixtures defined |

---

## 2. Detailed Integration Contracts

### 2.1 Security → Agent Core
- **Protocol:** `SecurityVerifier`
- **Side effects:** Executes authorized test against isolated demonstration target only; emits `ArtifactReference` logs.
- **Expected failures:** `TestRunnerError`, `IntegrationUnavailableError` -> Agent Core must hold incident in `UNVERIFIED` / `CONTAINMENT_FAILED` (fail closed).
- **Approval required:** No (restricted to authorized demo target).
- **Example `Finding` payload:**
```json
{
  "finding_id": "fnd_00000000000000000000000000000001",
  "incident_id": "inc_00000000000000000000000000000001",
  "category": "sql_injection",
  "affected_route": "/search",
  "affected_component": "search_service",
  "severity": "critical",
  "status": "reproduced",
  "evidence_ids": ["art_00000000000000000000000000000001"],
  "repository_revision": "rev_abc123def456",
  "environment": "demo-staging"
}
```

### 2.2 Platform → Agent Core
- **Protocols:** `FeatureStateReader`, `ApprovalReader`, `IncidentRepository`
- **Side effects:** None for reads; platform flag executor mutates Flagsmith only after valid `ApprovalDecision` and returns `OperationReceipt`.
- **Expected failures:** `UnknownFeatureError`, `InvalidApprovalError`, `ExpiredApprovalError`, `IntegrationUnavailableError`.
- **Example `FeatureState` readback response:**
```json
{
  "environment": "demo-staging",
  "feature_id": "fs_search_v1",
  "feature_name": "search_v1",
  "observation_status": "observed",
  "enabled": false,
  "observed_at": "2026-11-26T00:05:30Z",
  "observation_source": "actual_observed",
  "evidence_ids": ["art_00000000000000000000000000000003"]
}
```

### 2.3 Agent Core → Platform
- **Contracts:** `ContainmentProposal`, `InvestigationSummary`, `GroundedClaim`, `GroundingValidationReport`, `MappingResult`, `DependencyGraph`, `CoverageFinding`, `IncidentEvent`
- **Frontend Dashboard Contract:** `agent_core.investigator.format_investigation_dashboard_payload` serializes `investigation`, `validation` (`schema_valid`, `reference_checks_passed`, `contradiction_checks_passed`, `semantic_review_required`), and `execution` telemetry without requiring raw LLM prose parsing.
- **Side effects:** Persists proposal/events and redacted investigation artifact bundle; awaits human decision in `AWAITING_APPROVAL`.
- **Expected failures:** `AmbiguousMappingError`, `ContractValidationError`, `InvalidTransitionError`, `LLMResponseValidationError`.
- **Approval required:** **Mandatory (`approval_required=true`)** for `ContainmentProposal`.

### 2.4 Agent Core → Remediation
- **Contracts:** `IncidentRecord` (state `CONTAINED`), verified `Finding`, `VerificationResult` (`phase="after_containment"`, `passed=true`), source revision, and `evidence_ids`.
- **Side effects:** Initiates remediation planning only after containment is verified.
- **Expected failures:** `EvidenceValidationError` if containment is unverified.

### 2.5 Remediation → Security
- **Protocol:** `PatchTestRunner.submit_patch_test(proposal: PatchProposal) -> str`
- **Side effects:** Launches bounded isolated test execution strictly for `proposal.allowed_files` at `proposal.source_revision`.
- **Expected failures:** `PatchValidationError` (disallowed file path), `TestRunnerError`, `IntegrationUnavailableError`.
- **Approval required:** No (isolated test container; does not deploy to runtime).

### 2.6 Security → Remediation
- **Protocol:** `PatchTestRunner.get_patch_test_result(test_run_id: str) -> PatchTestResult`
- **Side effects:** Stores sanitized test log `ArtifactReference`.
- **Expected failures:** `RevisionMismatchError` if `tested_source_revision != expected_source_revision`; `TestExecutionStatus.INFRASTRUCTURE_ERROR` on timeout/crash.
- **Example `PatchTestResult`:**
```json
{
  "test_run_id": "trun_00000000000000000000000000000201",
  "patch_id": "pat_00000000000000000000000000000101",
  "incident_id": "inc_00000000000000000000000000000001",
  "expected_source_revision": "rev_abc123def456",
  "tested_source_revision": "rev_abc123def456",
  "tested_candidate_hash": "0e217d90d1e8684b801fe1c647573c9c6a6cfc65be16bdd24953d6db4c744931",
  "overall_status": "test_passed",
  "started_at": "2026-11-26T00:16:00Z",
  "completed_at": "2026-11-26T00:16:02Z"
}
```

### 2.7 Platform → Remediation
- **Protocols:** `DeploymentStateReader`, `FeatureStateReader`, `TelemetryReader`, `ApprovalReader`
- **Side effects:** Read-only observations.
- **Expected failures:** `DeploymentVerificationError`, `TelemetryUnavailableError` -> Remediation emits `RolloutDecision(decision_type="hold")` (fail closed).

### 2.8 Remediation → Platform
- **Contracts:** `PatchProposal`, `PatchTestResult`, `RolloutPlan`, `RolloutDecision`, `RollbackProposal`, `EvidenceReport`
- **Side effects:** Platform presents rollout/rollback proposals for human approval before mutating Flagsmith exposure percentages.
- **Expected failures:** `ContractValidationError`, `InvalidApprovalError`, `EvidenceValidationError`.
- **Approval required:** **Mandatory (`approval_required=true`)** for `RolloutPlan`, `RolloutDecision` stage transitions, and `RollbackProposal`.
