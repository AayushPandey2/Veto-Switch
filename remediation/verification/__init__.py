"""Phase 08 isolated patch verification package."""

from remediation.verification.acceptance import (
    build_rejected_preflight_decision,
    evaluate_verification_acceptance,
)
from remediation.verification.dashboard import (
    render_verification_markdown,
    serialize_verification_dashboard,
)
from remediation.verification.models import (
    FailureFeedback,
    IsolationPolicy,
    ObservedIsolationMetadata,
    PatchVerificationContext,
    PatchVerificationReport,
    RecoveryHandoff,
    RevisionVerification,
    TestPlanCompleteness,
    VerificationAcceptanceDecision,
    compute_expected_patched_revision,
)
from remediation.verification.validation import (
    build_mandatory_test_plan,
    validate_candidate_integrity,
    validate_evidence_integrity,
    validate_isolation_metadata,
    validate_revision_identity,
    validate_source_target_compatibility,
    validate_test_plan_completeness,
)

__all__ = [
    "FailureFeedback",
    "IsolationPolicy",
    "ObservedIsolationMetadata",
    "PatchVerificationContext",
    "PatchVerificationReport",
    "RecoveryHandoff",
    "RevisionVerification",
    "TestPlanCompleteness",
    "VerificationAcceptanceDecision",
    "build_mandatory_test_plan",
    "build_rejected_preflight_decision",
    "compute_expected_patched_revision",
    "evaluate_verification_acceptance",
    "render_verification_markdown",
    "serialize_verification_dashboard",
    "validate_candidate_integrity",
    "validate_evidence_integrity",
    "validate_isolation_metadata",
    "validate_revision_identity",
    "validate_source_target_compatibility",
    "validate_test_plan_completeness",
]
