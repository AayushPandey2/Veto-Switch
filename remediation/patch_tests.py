"""Phase 08 Isolated Patch Verification Orchestrator.

Coordinates deterministic pre-flight validation, isolated runner execution,
test-plan completeness, 5-point revision identity verification, evidence
integrity, and Phase 09 recovery handoff without LLM authority.
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable

from shared.contracts import EvidenceRepository, PatchTestRunner
from shared.enums import (
    EvidenceProvenance,
    PatchVerificationReasonCode,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    PatchProposal,
    PatchTestResult,
    VerificationResult,
)

from remediation.adapters.fixture_runner import FixturePatchTestRunner
from remediation.verification.acceptance import (
    build_rejected_preflight_decision,
    evaluate_verification_acceptance,
)
from remediation.verification.models import (
    PatchVerificationContext,
    PatchVerificationReport,
)
from remediation.verification.validation import (
    build_mandatory_test_plan,
    validate_candidate_integrity,
    validate_source_target_compatibility,
    validate_test_plan_completeness,
)


@runtime_checkable
class ExtendedPatchRunner(PatchTestRunner, Protocol):
    """Optional extended runner interface returning normalized result + artifacts."""

    async def execute_verified_run(
        self,
        proposal: PatchProposal,
        *,
        source_target: str,
        base_revision: str,
        test_ids: list[str],
        expected_patched_revision: str | None = None,
    ) -> tuple[PatchTestResult, list[ArtifactReference]]: ...


def _to_verification_result(
    ctx: PatchVerificationContext,
    result: PatchTestResult | None,
    accepted: bool,
    overall_status: TestExecutionStatus,
    limitations: list[str],
    artifacts: list[ArtifactReference],
    provenance: EvidenceProvenance,
) -> VerificationResult:
    """Build canonical VerificationResult(phase=AFTER_PATCH) from PatchVerificationReport."""
    verified_rev = (
        (result.runner_computed_patched_revision or result.tested_source_revision)
        if result is not None
        else ctx.authoritative_base_revision
    )
    artifact_ids = [a.artifact_id for a in artifacts]
    artifact_hashes = {a.artifact_id: a.content_hash for a in artifacts}
    passed_flag: bool | None = (
        None
        if overall_status in (TestExecutionStatus.NOT_RUN, TestExecutionStatus.INFRASTRUCTURE_ERROR)
        else accepted
    )
    vuln_repro: bool | None = (
        None
        if overall_status in (TestExecutionStatus.NOT_RUN, TestExecutionStatus.INFRASTRUCTURE_ERROR)
        else (not accepted)
    )
    return VerificationResult(
        verification_id=f"ver_{uuid.uuid4().hex[:32]}",
        incident_id=ctx.incident_id,
        test_id=",".join(build_mandatory_test_plan(ctx)) or "isolated_patch_suite",
        test_run_id=result.test_run_id if result is not None else None,
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=overall_status,
        passed=passed_flag,
        vulnerability_reproduced=vuln_repro,
        expected_revision=ctx.authoritative_base_revision,
        tested_revision=verified_rev,
        artifact_ids=artifact_ids,
        artifact_hashes=artifact_hashes,
        started_at=result.started_at if result is not None else utc_now(),
        completed_at=result.completed_at if result is not None else utc_now(),
        exit_code=result.exit_code if result is not None else None,
        infrastructure_error=(
            "; ".join(limitations)
            if overall_status == TestExecutionStatus.INFRASTRUCTURE_ERROR and limitations
            else None
        ),
        limitations=limitations,
        provenance=provenance,
    )


class IsolatedPatchVerificationOrchestrator:
    """Deterministic orchestrator for Phase 08 isolated patch verification."""

    def __init__(
        self,
        *,
        runner: PatchTestRunner | None = None,
        evidence_repo: EvidenceRepository | None = None,
    ) -> None:
        self._runner: PatchTestRunner = runner or FixturePatchTestRunner(scenario="pass")
        self._evidence_repo = evidence_repo

    async def verify_candidate(self, ctx: PatchVerificationContext) -> PatchVerificationReport:
        """Validate, execute in isolation, verify evidence, and build Phase 09 handoff."""
        now = utc_now()

        # 1. Source target compatibility gate (stand_in only; platform_demo_app -> not_run)
        target_ok, target_reasons, target_notes = validate_source_target_compatibility(
            ctx.source_target
        )
        if not target_ok:
            decision = build_rejected_preflight_decision(
                ctx,
                reason_codes=target_reasons,
                notes=target_notes,
                overall_status=TestExecutionStatus.NOT_RUN,
            )
            ver_result = _to_verification_result(
                ctx,
                None,
                False,
                TestExecutionStatus.NOT_RUN,
                decision.limitations,
                [],
                decision.evidence_provenance,
            )
            return PatchVerificationReport(
                patch_id=ctx.proposal.patch_id,
                incident_id=ctx.incident_id,
                source_target=ctx.source_target,
                candidate_tested=False,
                decision=decision,
                patch_test_result=None,
                verification_result=ver_result,
                artifacts=[],
                generated_at=now,
            )

        # 2. Candidate diff & hash integrity validation
        cand_ok, cand_reasons, cand_notes = validate_candidate_integrity(ctx)
        if not cand_ok:
            decision = build_rejected_preflight_decision(
                ctx,
                reason_codes=cand_reasons,
                notes=cand_notes,
                overall_status=TestExecutionStatus.NOT_RUN,
            )
            ver_result = _to_verification_result(
                ctx,
                None,
                False,
                TestExecutionStatus.NOT_RUN,
                decision.limitations,
                [],
                decision.evidence_provenance,
            )
            return PatchVerificationReport(
                patch_id=ctx.proposal.patch_id,
                incident_id=ctx.incident_id,
                source_target=ctx.source_target,
                candidate_tested=False,
                decision=decision,
                patch_test_result=None,
                verification_result=ver_result,
                artifacts=[],
                generated_at=now,
            )

        # 3. Mandatory test-plan completeness pre-flight
        plan_check = validate_test_plan_completeness(ctx, None)
        if not plan_check.complete:
            notes = [
                "Mandatory test plan incomplete: "
                f"missing_categories={plan_check.missing_categories}, "
                f"unknown_tests={plan_check.unknown_test_ids}"
            ]
            decision = build_rejected_preflight_decision(
                ctx,
                reason_codes=plan_check.reason_codes,
                notes=notes,
                overall_status=TestExecutionStatus.NOT_RUN,
                test_plan=plan_check,
            )
            ver_result = _to_verification_result(
                ctx,
                None,
                False,
                TestExecutionStatus.NOT_RUN,
                decision.limitations,
                [],
                decision.evidence_provenance,
            )
            return PatchVerificationReport(
                patch_id=ctx.proposal.patch_id,
                incident_id=ctx.incident_id,
                source_target=ctx.source_target,
                candidate_tested=False,
                decision=decision,
                patch_test_result=None,
                verification_result=ver_result,
                artifacts=[],
                generated_at=now,
            )

        # 4. Execute isolated patch tests through runner adapter
        test_ids = build_mandatory_test_plan(ctx)
        expected_patched = ctx.expected_patched_revision
        artifacts: list[ArtifactReference] = []
        if isinstance(self._runner, ExtendedPatchRunner):
            result, artifacts = await self._runner.execute_verified_run(
                ctx.proposal,
                source_target=ctx.source_target,
                base_revision=ctx.authoritative_base_revision,
                test_ids=test_ids,
                expected_patched_revision=expected_patched,
            )
        else:
            run_id = await self._runner.submit_patch_test(ctx.proposal)
            result = await self._runner.get_patch_test_result(run_id)
            if hasattr(self._runner, "get_run_artifacts"):
                artifacts = list(self._runner.get_run_artifacts(run_id))

        # Persist evidence artifacts if repository is wired
        if self._evidence_repo is not None:
            for art in artifacts:
                existing = await self._evidence_repo.get_artifact_reference(art.artifact_id)
                if existing is None:
                    await self._evidence_repo.store_artifact(
                        art, result.sanitized_logs.encode("utf-8")
                    )

        # 5. Deterministic acceptance decision
        decision = evaluate_verification_acceptance(ctx, result, artifacts)
        ver_result = _to_verification_result(
            ctx,
            result,
            decision.accepted,
            decision.overall_status,
            decision.limitations,
            artifacts,
            decision.evidence_provenance,
        )

        candidate_tested = decision.overall_status != TestExecutionStatus.NOT_RUN and (
            PatchVerificationReasonCode.UNSUPPORTED_SOURCE_TARGET not in decision.reason_codes
        )
        return PatchVerificationReport(
            patch_id=ctx.proposal.patch_id,
            incident_id=ctx.incident_id,
            source_target=ctx.source_target,
            candidate_tested=candidate_tested,
            decision=decision,
            patch_test_result=result,
            verification_result=ver_result,
            artifacts=artifacts,
            generated_at=utc_now(),
        )


async def verify_patch(
    patch_id: str,
    sandbox_target: str,
    *,
    ctx: PatchVerificationContext,
    runner: PatchTestRunner | None = None,
    evidence_repo: EvidenceRepository | None = None,
) -> VerificationResult:
    """Reconciled Phase 08 entrypoint returning canonical VerificationResult(AFTER_PATCH)."""
    if ctx.proposal.patch_id != patch_id:
        raise ValueError(
            f"Patch ID mismatch: requested {patch_id!r}, context has {ctx.proposal.patch_id!r}."
        )
    effective_ctx = ctx.model_copy(update={"sandbox_target": sandbox_target})
    orchestrator = IsolatedPatchVerificationOrchestrator(
        runner=runner, evidence_repo=evidence_repo
    )
    report = await orchestrator.verify_candidate(effective_ctx)
    if report.verification_result is None:
        raise RuntimeError("IsolatedPatchVerificationOrchestrator produced no VerificationResult.")
    return report.verification_result
