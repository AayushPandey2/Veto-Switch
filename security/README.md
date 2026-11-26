# `security/` — Security Verification & Isolated Execution

**Owner:** Cybersecurity Engineer

## Responsibilities

- Security scanner adapters producing normalized `shared.schemas.Finding` records
- Controlled vulnerability reproduction in authorized demonstration environments
- Post-containment security regression verification (`shared.schemas.VerificationResult`)
- Dependency vulnerability enrichment
- Isolated candidate patch test execution (`shared.contracts.PatchTestRunner` implementation)
- Security evidence artifact generation and SHA-256 hashing (`shared.schemas.ArtifactReference`)

## Integration Contracts

- Implements `shared.contracts.SecurityVerifier` and `shared.contracts.PatchTestRunner`.
- Consumes `PatchProposal` (with allowlisted `allowed_files` and `source_revision`) and returns `PatchTestResult`.
- Must enforce source revision matching and report `TestExecutionStatus.INFRASTRUCTURE_ERROR` on runner failures rather than fabricating pass/fail results.
- All security verification is restricted strictly to owned and authorized demonstration targets.

## Phase 01 Status

Ownership boundary and shared contracts defined in [`shared/contracts.py`](../shared/contracts.py) and [`docs/integration_contracts.md`](../docs/integration_contracts.md). Service implementations are intentionally deferred.
