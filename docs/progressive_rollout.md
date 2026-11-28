# Phase 09 — Progressive Rollout Intelligence

## Architecture

The deterministic Progressive Rollout Intelligence Engine (`remediation/rollout_agent.py`, `remediation/policies.py`, `remediation/release/`) operates without mandatory LLM calls:

1. **Recovery Eligibility Gate (`release/eligibility.py`)**: Enforces the 15-point eligibility check (trusted `PatchTestResult`, observed & addressable `DeploymentEvidence`, revision consistency, fresh `FeatureState`, contained `search_v1`, reference security verification, and segment targeting capability). Separates `draft_plan_available`, `eligible_for_review`, `eligible_for_stage_proposal`, and `authorized_for_execution`.
2. **Versioned Plan & Nested Cohorts (`release/planner.py`, `release/cohorts.py`)**: Builds 5/25/50/100% `RolloutPlan` with deterministic SHA-256 bucket assignment (`compute_cohort_bucket`, `assign_cohort`), preserving nested cohorts (`5% ⊂ 25% ⊂ 50% ⊂ 100%`).
3. **Immutable Stage Proposals & Approval Binding (`release/stage_proposal.py`)**: Binds `StageActionProposal` with canonical SHA-256 `proposal_hash` and `validate_stage_proposal_approval`.
4. **Deterministic Guardrails (`policies.py`)**: Evaluates absolute error rate (`<= 0.02`), baseline-relative error degradation (`<= 1.0 pp`), p95 latency degradation (`<= 20.0%`), minimum request count (`>= 100`), observation window (`>= 30s`), telemetry freshness, stage readback consistency, revision consistency, and security regression (`True` = pass, `False` = `rollback_proposed`, `None` = `hold`). Includes `wilson_confidence_interval`.
5. **Final-Stage Assessment & Phase 10 Handoff (`release/completion.py`, `release/dashboard.py`)**: Separates 100% completion (`assess_final_stage_completion`) from advancement and builds typed `RollbackHandoffContext` for Phase 10.

## Known Limitations

- Real Flagsmith percentage targeting and live telemetry collection depend on external `feat/platform` services.
- Synthetic telemetry in `remediation/adapters/fixture_telemetry.py` demonstrates policy logic only and never authorizes live exposure.
