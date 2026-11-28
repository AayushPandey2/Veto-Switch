"""Phase 09 Progressive Rollout Intelligence package."""

from remediation.release.cohorts import assign_cohort, compute_cohort_bucket
from remediation.release.completion import assess_final_stage_completion
from remediation.release.dashboard import (
    build_phase10_rollback_handoff,
    serialize_rollout_dashboard,
)
from remediation.release.eligibility import evaluate_recovery_eligibility
from remediation.release.models import (
    CohortAssignment,
    EligibilityGateResult,
    FinalRecoveryAssessment,
    RecoveryEligibilityContext,
    RecoveryEligibilityStatus,
    RollbackHandoffContext,
    RolloutEvaluationBundle,
    StageActionProposal,
    StageLifecycleState,
)
from remediation.release.planner import build_validated_rollout_plan
from remediation.release.stage_proposal import (
    build_stage_action_proposal,
    validate_stage_proposal_approval,
)
from remediation.release.telemetry_validator import validate_stage_telemetry

__all__ = [
    "CohortAssignment",
    "EligibilityGateResult",
    "FinalRecoveryAssessment",
    "RecoveryEligibilityContext",
    "RecoveryEligibilityStatus",
    "RollbackHandoffContext",
    "RolloutEvaluationBundle",
    "StageActionProposal",
    "StageLifecycleState",
    "assess_final_stage_completion",
    "assign_cohort",
    "build_phase10_rollback_handoff",
    "build_stage_action_proposal",
    "build_validated_rollout_plan",
    "compute_cohort_bucket",
    "evaluate_recovery_eligibility",
    "serialize_rollout_dashboard",
    "validate_stage_proposal_approval",
    "validate_stage_telemetry",
]
