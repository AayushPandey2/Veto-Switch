"""15-point deterministic Recovery Eligibility Gate and Deployment Identity validation."""

from __future__ import annotations

from shared.enums import (
    DeploymentStatus,
    FeatureObservationStatus,
    TestExecutionStatus,
)

from remediation.release.models import (
    EligibilityGateResult,
    RecoveryEligibilityContext,
    RecoveryEligibilityStatus,
)


def evaluate_recovery_eligibility(ctx: RecoveryEligibilityContext) -> EligibilityGateResult:
    """Independently validate all prerequisites before permitting actionable rollout planning."""
    missing: list[str] = []
    blocking: list[str] = []
    limitations: list[str] = []
    chain_verified = False

    # 1. Trusted passing patch verification
    ptr = ctx.patch_test_result
    if ptr is None:
        missing.append("patch_test_result")
    elif not ptr.is_trusted_pass:
        blocking.append("PatchTestResult is not a trusted passing isolated test run.")
    elif ptr.incident_id != ctx.incident_id:
        blocking.append("PatchTestResult belongs to a different incident.")
    elif (
        ctx.verified_patched_revision
        and ptr.tested_source_revision != ctx.verified_patched_revision
    ):
        blocking.append(
            "PatchTestResult tested_source_revision does not match verified_patched_revision."
        )

    # 2. Deployment evidence & addressability
    dep = ctx.deployment_evidence
    if dep is None:
        missing.append("deployment_evidence")
    else:
        if dep.deployment_status != DeploymentStatus.OBSERVED:
            missing.append("observed_deployment")
        if not dep.addressable:
            missing.append("addressable_deployment")
        if dep.environment != ctx.environment:
            blocking.append(
                f"Deployment environment {dep.environment!r} != target {ctx.environment!r}."
            )
        if dep.feature_name != ctx.target_feature:
            blocking.append(
                f"Deployment feature {dep.feature_name!r} != target {ctx.target_feature!r}."
            )
        if ctx.verified_patched_revision and dep.source_revision != ctx.verified_patched_revision:
            blocking.append(
                f"Deployment revision {dep.source_revision!r} != "
                f"verified {ctx.verified_patched_revision!r}."
            )
        if (
            ptr is not None
            and ptr.is_trusted_pass
            and dep.deployment_status == DeploymentStatus.OBSERVED
            and dep.addressable
            and (
                not ctx.verified_patched_revision
                or dep.source_revision == ptr.tested_source_revision
            )
        ):
            chain_verified = True

    # 3. Feature state freshness & legacy containment
    fs = ctx.current_feature_state
    if fs is None or fs.observation_status != FeatureObservationStatus.OBSERVED:
        missing.append("observed_current_feature_state")
    elif fs.environment != ctx.environment or fs.feature_name != ctx.target_feature:
        blocking.append("Current FeatureState target mismatch.")

    legacy = ctx.legacy_feature_state
    if legacy is not None:
        if legacy.observation_status != FeatureObservationStatus.OBSERVED:
            missing.append("observed_legacy_feature_state")
        elif legacy.enabled:
            blocking.append(
                f"Known vulnerable legacy feature {legacy.feature_name!r} is enabled; "
                "containment violated."
            )

    # 4. Reference security verification
    sec = ctx.reference_security_verification
    if sec is None:
        missing.append("reference_security_verification")
    elif sec.execution_status != TestExecutionStatus.TEST_PASSED or sec.passed is not True:
        blocking.append("Reference security verification has not passed.")

    # 5. Segment targeting support
    if not ctx.supports_segment_targeting:
        limitations.append(
            "Real segment targeting unavailable on executor; diagnostic plan only."
        )

    if blocking:
        return EligibilityGateResult(
            eligible=False,
            status=RecoveryEligibilityStatus.INELIGIBLE,
            missing_prerequisites=sorted(set(missing)),
            blocking_reasons=blocking,
            limitations=limitations,
            deployment_chain_verified=chain_verified,
        )

    if missing:
        return EligibilityGateResult(
            eligible=False,
            status=RecoveryEligibilityStatus.DRAFT_PLAN_AVAILABLE
            if not ctx.supports_segment_targeting
            else RecoveryEligibilityStatus.INELIGIBLE,
            missing_prerequisites=sorted(set(missing)),
            blocking_reasons=[f"Missing prerequisites: {', '.join(sorted(set(missing)))}"],
            limitations=limitations,
            deployment_chain_verified=chain_verified,
        )

    if not ctx.supports_segment_targeting:
        return EligibilityGateResult(
            eligible=False,
            status=RecoveryEligibilityStatus.DRAFT_PLAN_AVAILABLE,
            missing_prerequisites=["segment_targeting_executor_support"],
            limitations=limitations,
            deployment_chain_verified=chain_verified,
        )

    return EligibilityGateResult(
        eligible=True,
        status=RecoveryEligibilityStatus.ELIGIBLE_FOR_STAGE_PROPOSAL,
        missing_prerequisites=[],
        blocking_reasons=[],
        limitations=limitations,
        deployment_chain_verified=chain_verified,
    )
