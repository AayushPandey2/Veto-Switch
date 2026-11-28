"""Phase 10 Rollback Intelligence Engine and compatible public interface."""

from __future__ import annotations

from typing import Any

from shared.config import load_rollback_policy
from shared.enums import (
    EvidenceProvenance,
    RollbackFeasibilityStatus,
    RollbackReasonCode,
)
from shared.schemas import RollbackPolicyConfig, VerifiedSafeState

from remediation.recovery.candidate_generator import generate_candidate_strategies
from remediation.recovery.feasibility import evaluate_strategy_feasibility
from remediation.recovery.models import RollbackAnalysisResult, RollbackContext
from remediation.recovery.proposal_builder import build_rollback_proposal
from remediation.recovery.rollback_policy import select_rollback_strategy
from remediation.recovery.safe_state import resolve_last_verified_safe_state
from remediation.recovery.state_history import SafeStateHistoryStore
from remediation.recovery.trigger_validator import validate_rollback_trigger


class RollbackIntelligenceEngine:
    """Deterministic Phase 10 Rollback Intelligence Engine (zero mandatory LLM calls)."""

    def __init__(
        self,
        *,
        policy: RollbackPolicyConfig | None = None,
        history_store: SafeStateHistoryStore | None = None,
    ) -> None:
        self._policy = policy or load_rollback_policy()
        self._history_store = history_store or SafeStateHistoryStore()

    @property
    def history_store(self) -> SafeStateHistoryStore:
        return self._history_store

    def analyze(
        self,
        ctx: RollbackContext,
        *,
        history: list[VerifiedSafeState] | None = None,
    ) -> RollbackAnalysisResult:
        """Run the deterministic rollback analysis pipeline and emit an immutable proposal."""
        trigger_result = validate_rollback_trigger(ctx)
        stored_history = (
            list(history)
            if history is not None
            else self._history_store.list_for_incident(ctx.incident_id)
        )
        safe_state_result = resolve_last_verified_safe_state(
            stored_history, ctx, policy=self._policy
        )
        raw_candidates = generate_candidate_strategies(
            ctx, trigger_result, safe_state_result, policy=self._policy
        )
        evaluated = [
            evaluate_strategy_feasibility(c, ctx, trigger_result, safe_state_result)
            for c in raw_candidates
        ]
        selected = select_rollback_strategy(
            evaluated, trigger_result, safe_state_result, policy=self._policy
        )
        proposal = build_rollback_proposal(
            ctx,
            trigger_result,
            safe_state_result,
            selected,
            evaluated,
            policy=self._policy,
        )

        reason_codes: list[RollbackReasonCode] = []
        for rc in [
            *trigger_result.reason_codes,
            *safe_state_result.reason_codes,
            *selected.reason_codes,
            *(
                [RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED]
                if any(
                    RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED in c.reason_codes
                    for c in evaluated
                )
                else []
            ),
        ]:
            if rc not in reason_codes:
                reason_codes.append(rc)

        executable = (
            selected.feasibility_status == RollbackFeasibilityStatus.ELIGIBLE_FOR_EXECUTION_PROPOSAL
            and trigger_result.valid
        )
        explanation = (
            f"Trigger: {trigger_result.rationale} | "
            f"Safe state known: {safe_state_result.known} | "
            f"Selected strategy: {selected.strategy_type.value} "
            f"(feasibility={selected.feasibility_status.value})."
        )

        return RollbackAnalysisResult(
            incident_id=ctx.incident_id,
            trigger_validation=trigger_result,
            safe_state_resolution=safe_state_result,
            candidate_strategies=evaluated,
            selected_strategy=selected,
            proposal=proposal,
            executable_proposal=executable,
            manual_review_required=proposal.manual_review_required,
            reason_codes=reason_codes,
            limitations=list(proposal.safety_limitations),
            explanation_summary=explanation,
            explanation_provenance=EvidenceProvenance.DETERMINISTIC_REASONING,
        )


def propose_rollback(
    incident_id: str,
    last_good_state: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    """Compatible public roadmap interface.

    Security invariant: caller-supplied ``last_good_state`` is NEVER treated as
    authoritative verified-safe state evidence. Without persisted VerifiedSafeState
    history, ``last_verified_safe_state_known`` remains False and
    ``manual_review_required`` remains True.
    """
    _ = last_good_state  # Explicitly untrusted caller dict; never establishes safe state.
    ctx = RollbackContext(
        incident_id=incident_id,
        target_feature="search_v2",
        environment="demo-staging",
        manual_operator_request=True,
        manual_request_reason=reason,
        evidence_references=["ev_caller_rollback_request"],
    )
    engine = RollbackIntelligenceEngine()
    result = engine.analyze(ctx, history=[])
    if result.proposal is None:
        raise RuntimeError("RollbackIntelligenceEngine returned no proposal.")
    payload = result.proposal.model_dump(mode="json")
    payload["caller_last_good_state_ignored"] = True
    return payload
