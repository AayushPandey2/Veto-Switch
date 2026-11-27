# Phase 10 — Rollback Intelligence Engine

## Architecture

The deterministic Rollback Intelligence Engine (`remediation/rollback.py`, `remediation/recovery/`) operates without mandatory LLM calls:

1. **Trigger Validation (`trigger_validator.py`)**: Consumes `RolloutDecision` and telemetry, distinguishing confirmed security regressions, operational guardrail breaches, missing evidence (hold, never fabricated failure), and manual operator requests.
2. **Last Verified-Safe State (`safe_state.py`, `state_history.py`)**: Enforces an 11-point recording policy (`record_verified_safe_state`) and resolves the latest eligible `VerifiedSafeState` checkpoint (`resolve_last_verified_safe_state`) with explicit invalidation reasons (revision mismatch, stale age, routing/dependency conflict, security regression, legacy exposure, missing evidence).
3. **Bounded Candidate Generation & Feasibility (`candidate_generator.py`, `feasibility.py`, `rollback_policy.py`)**: Evaluates Strategies A–E under `config/rollback_policy.json`. Known vulnerable `search_v1` reactivation is strictly forbidden, partial exposure is rejected for confirmed security regressions, and targeting actions are marked `UNSUPPORTED` when the executor supports Boolean changes only.
4. **Immutable Proposal & Approval Binding (`proposal_builder.py`, `approval_binding.py`, `agent_core/approval_validator.py`)**: Builds `RollbackProposal` with canonical SHA-256 `proposal_hash`, typed `BooleanRollbackAction` / `TargetingRollbackAction`, and fresh human approval binding (`validate_rollback_approval_binding`). Pre-execution drift (`revalidate_rollback_preconditions`) rejects stale proposals.
5. **Receipt, Readback & Post-Rollback Verification (`receipt_validator.py`, `post_rollback_verifier.py`)**: Validates `OperationReceipt` (`execution_succeeded`, `execution_failed`, `execution_outcome_unknown`, `readback_pending`), reconciles management + application readback, and enforces security + functional verification. Full containment transitions to `CONTAINED` via `ROLLBACK_VERIFICATION_PASSED`; verified partial-exposure rollback transitions to `ROLLOUT_PAUSED` via `ROLLOUT_HOLD` and is never misclassified as `CONTAINED` or `RECOVERED`.
6. **Phase 11 Evidence Reporting Handoff (`dashboard.py`)**: `build_phase11_rollback_handoff` exports deterministic `Phase11RollbackHandoff` records from persisted events and artifacts.

## Offline Demonstrations & Evaluation

- Demos: `python -m remediation.rollback_demos` (primary synthetic error-spike + Demos A–J; all fixture-based).
- Evaluator: `python -m remediation.evaluations.rollback_evaluator` (24-case dataset in `remediation/evaluations/datasets/rollback_cases.json`).

## Known Limitations

- Phase 06 (`flag_auditor.py`) and Phase 09 (`rollout_agent.py`, `remediation/release/`) are not yet implemented on the `Feature` branch; rollback intelligence uses explicit fixture/contract interfaces.
- Live Flagsmith targeting execution and live post-rollback verification depend on external `feat/platform` and `feat/security` services.
