# Killswitch X — Approval Lifecycle & Executor Boundary

## 1. Proposal Identity & Canonical Hashing

Every containment change is represented by a `ContainmentProposal` whose `proposal_hash` is a deterministic SHA-256 digest over `CANONICAL_PROPOSAL_HASH_FIELDS`:
- `proposal_id`, `incident_id`, `proposal_type`
- `environment`, `flag_name`, `desired_enabled`, `expected_current_enabled`
- `registry_version`, `policy_version`, `approval_required`, `idempotency_token`

Changing any security-relevant field alters `proposal_hash` and invalidates any previously issued `ApprovalDecision`.

## 2. Authenticated Human Approval Boundary

[`agent_core/approval_validator.py`](../agent_core/approval_validator.py) enforces:
1. **Authenticated human channel:** `ProducerContext.authenticated` must be `True` and `actor_type == ActorType.HUMAN_OPERATOR`. AI agents (`ActorType.AI_AGENT`) cannot approve proposals.
2. **Exact identity & hash binding:** `approval.proposal_id`, `approval.incident_id`, and `approval.proposal_hash` must match the active, non-superseded proposal.
3. **Freshness via injected clock:** `decided_at <= now`, `approval.expires_at > now`, and `proposal.expires_at > now`.
4. **Feature-state drift protection:** Current `FeatureState` must be `OBSERVED` and match `proposal.expected_current_enabled`. If Flagsmith state changed while awaiting approval, execution is blocked and re-approval is required.
5. **Single-use consumption:** Consumed `approval_id`s are recorded atomically on `IncidentAggregate.consumed_approval_ids` during `commit_transition`. Stage approvals in `ROLLOUT_PENDING` cannot reuse prior stage `approval_id`s.

## 3. Stale & Rejected Approvals

- **Rejection (`approval_rejected`):** Transitions to `REJECTED`, supersedes the proposal, preserves audit history, and emits **zero** execution requests. Reconsideration requires generating a new proposal.
- **Expiration (`approval_expired` or clock past `expires_at`):** Denied deterministically with `APPROVAL_EXPIRED`.

## 4. Executor Boundary

`IncidentOrchestrator` **never** calls Flagsmith write APIs. Upon `approval_granted`, `ApprovalGrantedHandler` emits a `DownstreamRequest` carrying the stable `idempotency_key`. In fixture simulations, `executable_live` is strictly `False` (`is_synthetic_fixture=True`). Only the trusted platform executor consumes live requests and reports back an `OperationReceipt`.
