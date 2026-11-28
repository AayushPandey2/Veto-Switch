"""Deterministic acceptance logic, Phase 07 failure feedback, and Phase 09 handoff."""

from __future__ import annotations

from shared.enums import (
    EvidenceProvenance,
    PatchVerificationReasonCode,
    TestExecutionStatus,
)
from shared.schemas import ArtifactReference, PatchTestResult

from remediation.verification.models import (
    FailureFeedback,
    PatchVerificationContext,
    RecoveryHandoff,
    RevisionVerification,
    TestPlanCompleteness,
    VerificationAcceptanceDecision,
)
from remediation.verification.validation import (
    validate_evidence_integrity,
    validate_isolation_metadata,
    validate_revision_identity,
    validate_test_plan_completeness,
)


def evaluate_verification_acceptance(
    ctx: PatchVerificationContext,
    result: PatchTestResult,
    artifacts: list[ArtifactReference],
) -> VerificationAcceptanceDecision:
    """Produce the final deterministic acceptance decision for an isolated patch test run."""
    reasons: list[PatchVerificationReasonCode] = []
    limitations = list(result.limitations)

    test_plan = validate_test_plan_completeness(ctx, result)
    reasons.extend(test_plan.reason_codes)

    revision_check = validate_revision_identity(ctx, result)
    reasons.extend(revision_check.reason_codes)

    isolation_valid, iso_reasons, iso_notes = validate_isolation_metadata(
        ctx.isolation_policy,
        result.isolation_metadata,
        fixture_mode=ctx.fixture_mode,
    )
    reasons.extend(iso_reasons)
    limitations.extend(iso_notes)

    evidence_valid, ev_reasons, ev_notes = validate_evidence_integrity(
        result, artifacts, fixture_mode=ctx.fixture_mode
    )
    reasons.extend(ev_reasons)
    limitations.extend(ev_notes)

    failed_tests: list[str] = []
    security_set = set(ctx.required_security_tests)
    functional_set = set(ctx.required_functional_tests) | set(ctx.required_negative_input_tests)
    smoke_set = set(ctx.required_smoke_tests)

    for outcome in result.individual_outcomes:
        if outcome.status == TestExecutionStatus.TEST_PASSED:
            continue
        failed_tests.append(outcome.test_name)
        if outcome.status == TestExecutionStatus.INFRASTRUCTURE_ERROR:
            reasons.append(PatchVerificationReasonCode.RUNNER_INFRASTRUCTURE_ERROR)
        elif outcome.status == TestExecutionStatus.NOT_RUN:
            reasons.append(PatchVerificationReasonCode.PARTIAL_RESULTS_REJECTED)
        elif outcome.test_name in security_set or outcome.category == "security":
            reasons.append(PatchVerificationReasonCode.SECURITY_REGRESSION_FAILED)
        elif outcome.test_name in smoke_set or outcome.category == "smoke":
            reasons.append(PatchVerificationReasonCode.SMOKE_TEST_FAILED)
        elif outcome.test_name in functional_set or outcome.category in (
            "functional",
            "negative_input",
        ):
            reasons.append(PatchVerificationReasonCode.FUNCTIONAL_REGRESSION_FAILED)
        else:
            reasons.append(PatchVerificationReasonCode.FUNCTIONAL_REGRESSION_FAILED)

    if result.overall_status == TestExecutionStatus.INFRASTRUCTURE_ERROR:
        reasons.append(PatchVerificationReasonCode.RUNNER_INFRASTRUCTURE_ERROR)
    elif result.overall_status == TestExecutionStatus.NOT_RUN:
        reasons.append(PatchVerificationReasonCode.PARTIAL_RESULTS_REJECTED)
    elif result.overall_status == TestExecutionStatus.TEST_FAILED and not failed_tests:
        reasons.append(PatchVerificationReasonCode.FUNCTIONAL_REGRESSION_FAILED)

    if not result.individual_outcomes:
        reasons.append(PatchVerificationReasonCode.PARTIAL_RESULTS_REJECTED)

    deduped_reasons = list(dict.fromkeys(reasons))
    accepted = (
        len(deduped_reasons) == 0
        and result.is_trusted_pass
        and test_plan.complete
        and revision_check.consistent
        and isolation_valid
        and evidence_valid
    )

    if accepted:
        deduped_reasons = [PatchVerificationReasonCode.VERIFIED_READY_FOR_DEPLOYMENT]
        overall_status = TestExecutionStatus.TEST_PASSED
        target_state = "patch_tested"
        handoff: RecoveryHandoff | None = RecoveryHandoff(
            incident_id=ctx.incident_id,
            patch_id=ctx.proposal.patch_id,
            test_run_id=result.test_run_id,
            candidate_tested=True,
            ready_for_deployment_verification=True,
            deployment_verified=False,
            rollout_authorized=False,
            tested_candidate_hash=result.tested_candidate_hash,
            tested_source_revision=result.tested_source_revision,
            patched_revision=result.runner_computed_patched_revision,
            artifact_ids=list(result.artifact_ids),
            limitations=list(dict.fromkeys(limitations)),
        )
        feedback: FailureFeedback | None = None
    else:
        if any(
            r
            in (
                PatchVerificationReasonCode.RUNNER_UNAVAILABLE,
                PatchVerificationReasonCode.RUNNER_TIMEOUT_OUTCOME_UNKNOWN,
                PatchVerificationReasonCode.RUNNER_INFRASTRUCTURE_ERROR,
                PatchVerificationReasonCode.INSUFFICIENT_ISOLATION,
                PatchVerificationReasonCode.EVIDENCE_MISSING,
                PatchVerificationReasonCode.EVIDENCE_CORRUPTED,
                PatchVerificationReasonCode.EVIDENCE_PROVENANCE_UNTRUSTED,
            )
            for r in deduped_reasons
        ):
            overall_status = TestExecutionStatus.INFRASTRUCTURE_ERROR
            target_state = "patch_pending"
        elif result.overall_status == TestExecutionStatus.NOT_RUN and not failed_tests:
            overall_status = TestExecutionStatus.NOT_RUN
            target_state = "patch_pending"
        else:
            overall_status = TestExecutionStatus.TEST_FAILED
            target_state = "patch_pending"

        handoff = None
        retry_eligible = overall_status in (
            TestExecutionStatus.TEST_FAILED,
            TestExecutionStatus.INFRASTRUCTURE_ERROR,
        )
        feedback = FailureFeedback(
            patch_id=ctx.proposal.patch_id,
            incident_id=ctx.incident_id,
            retry_eligible=retry_eligible,
            reason_codes=deduped_reasons,
            failed_tests=sorted(set(failed_tests)),
            missing_tests=list(test_plan.missing_test_ids),
            revision_notes=list(revision_check.mismatches),
            limitations=list(dict.fromkeys(limitations)),
            summary=(
                f"Isolated verification did not accept patch {ctx.proposal.patch_id}: "
                + ", ".join(r.value for r in deduped_reasons)
            ),
        )

    provenance = (
        EvidenceProvenance.REFERENCE_FIXTURE
        if ctx.fixture_mode and result.provenance == EvidenceProvenance.REFERENCE_FIXTURE
        else result.provenance
    )

    return VerificationAcceptanceDecision(
        accepted=accepted,
        overall_status=overall_status,
        target_state_recommendation=target_state,
        reason_codes=deduped_reasons,
        test_plan=test_plan,
        revision_check=revision_check,
        isolation_valid=isolation_valid,
        evidence_valid=evidence_valid,
        evidence_provenance=provenance,
        limitations=list(dict.fromkeys(limitations)),
        recovery_handoff=handoff,
        failure_feedback=feedback,
    )


def build_rejected_preflight_decision(
    ctx: PatchVerificationContext,
    *,
    reason_codes: list[PatchVerificationReasonCode],
    notes: list[str],
    overall_status: TestExecutionStatus = TestExecutionStatus.NOT_RUN,
    test_plan: TestPlanCompleteness | None = None,
) -> VerificationAcceptanceDecision:
    """Build deterministic non-passing decision when pre-flight checks block execution."""
    plan = test_plan or validate_test_plan_completeness(ctx, None)
    revision_check = RevisionVerification(
        consistent=False,
        base_source_revision=ctx.authoritative_base_revision,
        candidate_content_hash=ctx.proposal.candidate_content_hash,
        expected_patched_revision=ctx.expected_patched_revision,
        mismatches=list(notes),
        reason_codes=list(reason_codes),
    )
    feedback = FailureFeedback(
        patch_id=ctx.proposal.patch_id,
        incident_id=ctx.incident_id,
        retry_eligible=PatchVerificationReasonCode.UNSUPPORTED_SOURCE_TARGET not in reason_codes,
        reason_codes=list(reason_codes),
        missing_tests=list(plan.missing_test_ids),
        revision_notes=list(notes),
        limitations=list(notes),
        summary="Pre-flight blocked isolated patch verification: "
        + ", ".join(r.value for r in reason_codes),
    )
    return VerificationAcceptanceDecision(
        accepted=False,
        overall_status=overall_status,
        target_state_recommendation="patch_pending",
        reason_codes=list(reason_codes),
        test_plan=plan,
        revision_check=revision_check,
        isolation_valid=False,
        evidence_valid=False,
        evidence_provenance=(
            EvidenceProvenance.REFERENCE_FIXTURE
            if ctx.fixture_mode
            else EvidenceProvenance.SECURITY_TEST_OUTPUT
        ),
        limitations=list(notes),
        recovery_handoff=None,
        failure_feedback=feedback,
    )
