"""Deterministic claim-to-evidence linking and lifecycle-aware completeness evaluation."""

from __future__ import annotations

from shared.enums import (
    ApprovalStatus,
    DeploymentStatus,
    EvidenceCompleteness,
    EvidenceProvenance,
    IncidentState,
    OperationOutcome,
    TestExecutionStatus,
    VerificationPhase,
)

from remediation.reporting.models import (
    ArtifactIntegrityResult,
    ArtifactIntegrityStatus,
    ClaimEvidenceLink,
    EvidenceReportContext,
    MissingEvidenceItem,
)


def build_claim_evidence_links(
    ctx: EvidenceReportContext,
    integrity_results: list[ArtifactIntegrityResult],
) -> list[ClaimEvidenceLink]:
    """Build explicit claim-to-evidence links without deriving truth from IncidentState alone."""
    claims: list[ClaimEvidenceLink] = []
    corrupted_ids = {
        r.artifact_id
        for r in integrity_results
        if r.status
        in (
            ArtifactIntegrityStatus.HASH_MISMATCH,
            ArtifactIntegrityStatus.SIZE_MISMATCH,
            ArtifactIntegrityStatus.INCIDENT_MISMATCH,
        )
    }

    # 1. Vulnerability reproduced
    repro_results = [
        v for v in ctx.verification_results if v.phase == VerificationPhase.BEFORE_CONTAINMENT
    ]
    if repro_results:
        vr = repro_results[-1]
        has_corruption = any(aid in corrupted_ids for aid in vr.artifact_ids)
        ok = (
            vr.execution_status == TestExecutionStatus.TEST_PASSED
            and vr.vulnerability_reproduced is True
            and not has_corruption
        )
        claims.append(
            ClaimEvidenceLink(
                claim_id="claim_vulnerability_reproduced",
                claim_type="vulnerability_reproduction",
                claim_description=(
                    "Original security vulnerability reproduced in target environment."
                ),
                incident_id=ctx.incident_id,
                related_record_ids=[vr.verification_id],
                supporting_artifact_ids=list(vr.artifact_ids),
                evidence_provenance=vr.provenance,
                verification_status=(
                    "contradicted"
                    if has_corruption
                    else ("verified" if ok else "unverified")
                ),
                limitations=["Corrupted artifact detected."] if has_corruption else [],
            )
        )

    # 2. Human approval recorded
    approved = [a for a in ctx.approvals if a.decision == ApprovalStatus.APPROVED]
    if approved:
        appr = approved[-1]
        claims.append(
            ClaimEvidenceLink(
                claim_id="claim_human_approval",
                claim_type="human_authorization",
                claim_description=(
                    f"Authenticated human operator approved proposal {appr.proposal_id}."
                ),
                incident_id=ctx.incident_id,
                related_record_ids=[appr.approval_id, appr.proposal_id],
                evidence_provenance=EvidenceProvenance.ACTUAL_OBSERVED,
                verification_status="verified",
            )
        )

    # 3. External operation executed
    succeeded_ops = [o for o in ctx.operation_receipts if o.outcome == OperationOutcome.SUCCEEDED]
    if succeeded_ops:
        op = succeeded_ops[-1]
        claims.append(
            ClaimEvidenceLink(
                claim_id="claim_flag_operation_executed",
                claim_type="external_execution",
                claim_description=f"External executor updated feature {op.target_feature!r}.",
                incident_id=ctx.incident_id,
                related_record_ids=[op.operation_id, op.proposal_id, op.approval_id],
                supporting_artifact_ids=list(op.evidence_ids),
                evidence_provenance=op.provenance,
                verification_status="verified" if ctx.feature_state_observations else "unverified",
                limitations=(
                    ["Operation receipt recorded without independent feature-state readback."]
                    if not ctx.feature_state_observations
                    else []
                ),
            )
        )

    # 4. Containment verified
    post_cont = [
        v for v in ctx.verification_results if v.phase == VerificationPhase.AFTER_CONTAINMENT
    ]
    if post_cont:
        cv = post_cont[-1]
        has_corruption = any(aid in corrupted_ids for aid in cv.artifact_ids)
        ok = (
            cv.execution_status == TestExecutionStatus.TEST_PASSED
            and cv.passed is True
            and cv.vulnerability_reproduced is False
            and bool(ctx.operation_receipts)
            and bool(ctx.feature_state_observations)
            and not has_corruption
        )
        claims.append(
            ClaimEvidenceLink(
                claim_id="claim_containment_verified",
                claim_type="containment_verification",
                claim_description=(
                    "Post-containment security verification passed with observed readback."
                ),
                incident_id=ctx.incident_id,
                related_record_ids=[cv.verification_id],
                supporting_artifact_ids=list(cv.artifact_ids),
                evidence_provenance=cv.provenance,
                verification_status=(
                    "contradicted" if has_corruption else ("verified" if ok else "unverified")
                ),
            )
        )

    # 5. Patch tested
    if ctx.patch_test_results:
        ptr = ctx.patch_test_results[-1]
        has_corruption = any(aid in corrupted_ids for aid in ptr.artifact_ids)
        claims.append(
            ClaimEvidenceLink(
                claim_id="claim_patch_tested",
                claim_type="patch_verification",
                claim_description=f"Candidate patch {ptr.patch_id} isolated verification.",
                incident_id=ctx.incident_id,
                related_record_ids=[ptr.test_run_id, ptr.patch_id],
                supporting_artifact_ids=list(ptr.artifact_ids),
                evidence_provenance=ptr.provenance,
                verification_status=(
                    "contradicted"
                    if has_corruption
                    else ("verified" if ptr.is_trusted_pass else "unverified")
                ),
            )
        )

    # 6. Patch deployed
    if ctx.deployment_evidence:
        dep = ctx.deployment_evidence[-1]
        ok = dep.deployment_status == DeploymentStatus.OBSERVED and dep.addressable
        claims.append(
            ClaimEvidenceLink(
                claim_id="claim_patch_deployed",
                claim_type="deployment_verification",
                claim_description=(
                    f"Patched implementation {dep.implementation_id} deployed and addressable."
                ),
                incident_id=ctx.incident_id,
                related_record_ids=[dep.deployment_id],
                supporting_artifact_ids=list(dep.evidence_ids),
                evidence_provenance=dep.provenance,
                verification_status="verified" if ok else "unverified",
            )
        )

    return claims


def evaluate_report_completeness(
    ctx: EvidenceReportContext,
    claims: list[ClaimEvidenceLink],
    integrity_results: list[ArtifactIntegrityResult],
    inconsistencies: list[str],
) -> tuple[EvidenceCompleteness, list[MissingEvidenceItem], list[str]]:
    """Evaluate lifecycle-aware completeness and build UNVERIFIED / INCOMPLETE entries."""
    missing_items: list[MissingEvidenceItem] = []
    limitations: list[str] = []

    if not ctx.coverage_findings:
        limitations.append("Coverage audit (Phase 06): NOT AVAILABLE / NOT IMPLEMENTED.")

    if ctx.fixture_mode:
        limitations.append("Report generated in fixture mode using synthetic/reference records.")

    corrupted = [
        r
        for r in integrity_results
        if r.status
        in (
            ArtifactIntegrityStatus.HASH_MISMATCH,
            ArtifactIntegrityStatus.SIZE_MISMATCH,
            ArtifactIntegrityStatus.INCIDENT_MISMATCH,
        )
    ]
    for c in corrupted:
        missing_items.append(
            MissingEvidenceItem(
                missing_evidence_type="corrupted_artifact",
                affected_claim=f"Artifact {c.artifact_id}",
                required_record=c.artifact_id,
                reason=c.message,
                impact="Claims relying on this artifact cannot remain verified.",
                recommended_follow_up=(
                    "Re-acquire and verify original artifact bytes from trusted store."
                ),
            )
        )

    # Lifecycle-specific required evidence
    if ctx.incident_status in (
        IncidentState.CONTAINED,
        IncidentState.PATCH_PENDING,
        IncidentState.PATCH_TESTED,
        IncidentState.ROLLOUT_PENDING,
        IncidentState.RECOVERED,
    ):
        if not ctx.operation_receipts:
            missing_items.append(
                MissingEvidenceItem(
                    missing_evidence_type="missing_operation_receipt",
                    affected_claim="Containment execution",
                    required_record="OperationReceipt",
                    reason="No external OperationReceipt recorded.",
                    impact="Cannot confirm external feature-flag mutation occurred.",
                    recommended_follow_up=(
                        "Retrieve trusted OperationReceipt from platform executor."
                    ),
                )
            )
        if not ctx.feature_state_observations:
            missing_items.append(
                MissingEvidenceItem(
                    missing_evidence_type="missing_feature_readback",
                    affected_claim="Effective feature state",
                    required_record="FeatureState",
                    reason="No independent FeatureState readback recorded.",
                    impact="Provider acceptance does not prove application feature state.",
                    recommended_follow_up="Record readback FeatureState observation.",
                )
            )

    if ctx.incident_status == IncidentState.RECOVERED:
        if not ctx.deployment_evidence:
            missing_items.append(
                MissingEvidenceItem(
                    missing_evidence_type="missing_deployment_evidence",
                    affected_claim="Patched implementation deployed",
                    required_record="DeploymentEvidence",
                    reason="No DeploymentEvidence recorded for RECOVERED incident.",
                    impact="Cannot establish that tested candidate patch was deployed.",
                    recommended_follow_up="Provide trusted DeploymentEvidence and revision check.",
                )
            )
        if not ctx.rollout_plans or not ctx.rollout_decisions:
            missing_items.append(
                MissingEvidenceItem(
                    missing_evidence_type="missing_rollout_evidence",
                    affected_claim="Progressive recovery verified",
                    required_record="RolloutPlan / RolloutDecision",
                    reason="Progressive rollout plan or stage decisions missing.",
                    impact="Recovery cannot be verified without stage guardrail evidence.",
                    recommended_follow_up="Record RolloutPlan and all stage RolloutDecisions.",
                )
            )

    if not ctx.accepted_events:
        missing_items.append(
            MissingEvidenceItem(
                missing_evidence_type="missing_event_history",
                affected_claim="Incident timeline",
                required_record="IncidentEvent",
                reason="No accepted IncidentEvent records available.",
                impact="Timeline and causal state transitions cannot be reconstructed.",
                recommended_follow_up="Retrieve accepted incident events from repository.",
            )
        )

    if inconsistencies:
        limitations.extend(inconsistencies)

    if not ctx.accepted_events or corrupted or inconsistencies or missing_items:
        completeness = EvidenceCompleteness.INCOMPLETE
    elif any(c.verification_status == "unverified" for c in claims):
        completeness = EvidenceCompleteness.PARTIAL
    else:
        completeness = EvidenceCompleteness.COMPLETE

    return completeness, missing_items, limitations
