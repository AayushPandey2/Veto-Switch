"""Uncertainty decomposition separating completeness, reproduction, and claim validity."""

from __future__ import annotations

from pydantic import Field, StrictBool
from shared.enums import (
    EvidenceCompleteness,
    EvidenceSupportLevel,
    FindingStatus,
    InvestigationStatus,
    VulnerabilityCategory,
)
from shared.schemas import GroundingValidationReport, KillswitchModel

from agent_core.intelligence.confidence import (
    QualitativeConfidenceAssessment,
    assess_evidence_support,
)
from agent_core.intelligence.investigation_context import InvestigationContext


class UncertaintyAssessment(KillswitchModel):
    """Separates distinct epistemic dimensions cleanly without conflating them."""

    evidence_completeness: EvidenceCompleteness
    reproduction_status: FindingStatus
    claim_validation_passed: StrictBool
    investigation_status: InvestigationStatus
    model_reported_confidence: str | None = None
    confidence_assessment: QualitativeConfidenceAssessment
    uncertainties: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    requires_manual_review: StrictBool = False
    manual_review_reasons: list[str] = Field(default_factory=list)


def evaluate_uncertainty(
    *,
    context: InvestigationContext,
    grounding_report: GroundingValidationReport | None,
    model_uncertainties: list[str] | None = None,
    model_missing: list[str] | None = None,
    model_reported_confidence: str | None = None,
    has_untrusted_anomalies: bool = False,
) -> UncertaintyAssessment:
    """Compute investigation completeness, missing evidence, and manual review requirements."""
    conf = assess_evidence_support(context=context, grounding_report=grounding_report)

    if conf.evidence_support_level == EvidenceSupportLevel.HIGH_EVIDENCE_SUPPORT:
        ev_comp = EvidenceCompleteness.COMPLETE
    elif conf.evidence_support_level in {
        EvidenceSupportLevel.MODERATE_EVIDENCE_SUPPORT,
        EvidenceSupportLevel.LIMITED_EVIDENCE_SUPPORT,
    }:
        ev_comp = EvidenceCompleteness.PARTIAL
    else:
        ev_comp = EvidenceCompleteness.INCOMPLETE

    uncertainties = list(dict.fromkeys([*(model_uncertainties or []), *context.known_limitations]))
    missing = list(
        dict.fromkeys(
            [*(model_missing or []), *context.missing_information, *conf.missing_conditions]
        )
    )

    manual_reasons: list[str] = []
    if context.finding.category == VulnerabilityCategory.OTHER:
        manual_reasons.append("unsupported_or_unknown_vulnerability_category")
    if context.verification_summary.conflicting_outcomes:
        manual_reasons.append("contradictory_verification_evidence")
    if grounding_report is not None and not grounding_report.overall_valid:
        manual_reasons.append("grounding_or_contradiction_failure")
    if has_untrusted_anomalies:
        manual_reasons.append("anomalous_or_rejected_untrusted_content")
    if any(
        ex.reason_code in {"REVISION_MISMATCH", "ENVIRONMENT_MISMATCH", "INCIDENT_MISMATCH"}
        for ex in context.excluded_items
    ):
        manual_reasons.append("excluded_mismatched_artifacts")

    requires_review = bool(manual_reasons)
    claim_valid = True if grounding_report is None else grounding_report.overall_valid

    if requires_review:
        inv_status = InvestigationStatus.MANUAL_REVIEW_REQUIRED
    elif conf.evidence_support_level == EvidenceSupportLevel.INSUFFICIENT_EVIDENCE:
        inv_status = InvestigationStatus.INSUFFICIENT_EVIDENCE
    elif missing:
        inv_status = InvestigationStatus.PARTIAL
    else:
        inv_status = InvestigationStatus.COMPLETED

    return UncertaintyAssessment(
        evidence_completeness=ev_comp,
        reproduction_status=context.finding.status,
        claim_validation_passed=claim_valid,
        investigation_status=inv_status,
        model_reported_confidence=model_reported_confidence,
        confidence_assessment=conf,
        uncertainties=uncertainties,
        missing_evidence=missing,
        requires_manual_review=requires_review,
        manual_review_reasons=manual_reasons,
    )
