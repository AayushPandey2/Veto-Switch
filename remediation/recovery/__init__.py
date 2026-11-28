"""Phase 10 Rollback Intelligence package."""

from remediation.recovery.approval_binding import (
    revalidate_rollback_preconditions,
    validate_rollback_approval_binding,
)
from remediation.recovery.candidate_generator import generate_candidate_strategies
from remediation.recovery.dashboard import (
    build_phase11_rollback_handoff,
    serialize_rollback_dashboard,
)
from remediation.recovery.feasibility import evaluate_strategy_feasibility
from remediation.recovery.models import (
    CheckpointInvalidation,
    ExecutorCapabilities,
    Phase11RollbackHandoff,
    PostRollbackVerificationResult,
    ReadbackReconciliationResult,
    RollbackAnalysisResult,
    RollbackCandidateStrategy,
    RollbackContext,
    RollbackReceiptValidationResult,
    SafeStateResolutionResult,
    TriggerValidationResult,
)
from remediation.recovery.post_rollback_verifier import (
    reconcile_post_rollback_readback,
    verify_post_rollback,
)
from remediation.recovery.proposal_builder import build_rollback_proposal
from remediation.recovery.receipt_validator import validate_rollback_receipt
from remediation.recovery.rollback_policy import select_rollback_strategy
from remediation.recovery.safe_state import (
    SafeStateCheckpointInput,
    record_verified_safe_state,
    resolve_last_verified_safe_state,
)
from remediation.recovery.state_history import SafeStateHistoryStore
from remediation.recovery.trigger_validator import validate_rollback_trigger

__all__ = [
    "CheckpointInvalidation",
    "ExecutorCapabilities",
    "Phase11RollbackHandoff",
    "PostRollbackVerificationResult",
    "ReadbackReconciliationResult",
    "RollbackAnalysisResult",
    "RollbackCandidateStrategy",
    "RollbackContext",
    "RollbackReceiptValidationResult",
    "SafeStateCheckpointInput",
    "SafeStateHistoryStore",
    "SafeStateResolutionResult",
    "TriggerValidationResult",
    "build_phase11_rollback_handoff",
    "build_rollback_proposal",
    "evaluate_strategy_feasibility",
    "generate_candidate_strategies",
    "reconcile_post_rollback_readback",
    "record_verified_safe_state",
    "resolve_last_verified_safe_state",
    "revalidate_rollback_preconditions",
    "select_rollback_strategy",
    "serialize_rollback_dashboard",
    "validate_rollback_approval_binding",
    "validate_rollback_receipt",
    "validate_rollback_trigger",
    "verify_post_rollback",
]
