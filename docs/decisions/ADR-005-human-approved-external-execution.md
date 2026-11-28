# ADR-005: Human-Approved External Execution

## Context
Disabling a feature flag, advancing progressive exposure, or rolling back an implementation affects live availability and security posture.

## Decision
Require every `ContainmentProposal` (`approval_required=True`) and `RollbackProposal` (`approval_required=True`) to be bound to a canonical SHA-256 `proposal_hash` and executed only after an authenticated, non-expired `ApprovalDecision` passes deterministic validation (`validate_approval_for_proposal`).

## Alternatives
1. Auto-approving low-disruption containment proposals.
2. Binding approvals only to mutable proposal IDs without payload hashing.

## Rationale
Binding approvals to the exact canonical hash of security-relevant fields prevents TOCTOU tampering, stale approvals, and accidental mis-execution.

## Consequences
- Platform executor must re-verify `proposal_hash`, expiration, and `authorization_context_ref` before calling Flagsmith and must emit an `OperationReceipt`.

## Known Limitations
Operator availability becomes part of time-to-contain; proposal expiration (`default_proposal_expiration_seconds=900`) requires re-proposal if review times out.
