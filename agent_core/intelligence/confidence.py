"""Explainable qualitative evidence-support classification (Section 18).

Avoids misleading calibrated probabilities or fake risk percentages.
"""

from __future__ import annotations

from pydantic import Field, StrictBool
from shared.enums import EvidenceSupportLevel, FindingStatus
from shared.schemas import GroundingValidationReport, KillswitchModel

from agent_core.intelligence.investigation_context import InvestigationContext


class QualitativeConfidenceAssessment(KillswitchModel):
    """Transparent qualitative evidence assessment based strictly on observed conditions."""

    evidence_support_level: EvidenceSupportLevel
    reproduction_evidence_present: StrictBool
    relevant_source_excerpt_present: StrictBool
    environment_consistent: StrictBool
    revision_consistent: StrictBool
    evidence_internally_consistent: StrictBool
    grounding_valid: StrictBool
    missing_conditions: list[str] = Field(default_factory=list)
    rationale: str = Field(min_length=1)


def assess_evidence_support(
    *,
    context: InvestigationContext,
    grounding_report: GroundingValidationReport | None,
) -> QualitativeConfidenceAssessment:
    """Derive qualitative ``EvidenceSupportLevel`` deterministically from supplied evidence."""
    repro_present = (
        context.finding.status == FindingStatus.REPRODUCED
        and context.verification_summary.reproduction_outcome == "reproduced"
    )
    source_present = bool(context.bounded_source_excerpts)
    excluded_reasons = {ex.reason_code for ex in context.excluded_items}
    env_consistent = "ENVIRONMENT_MISMATCH" not in excluded_reasons
    rev_consistent = "REVISION_MISMATCH" not in excluded_reasons
    internally_consistent = not context.verification_summary.conflicting_outcomes
    grounding_valid = True if grounding_report is None else grounding_report.overall_valid

    missing: list[str] = list(context.missing_information)
    if not env_consistent:
        missing.append("environment_consistent_evidence")
    if not rev_consistent:
        missing.append("revision_consistent_evidence")
    if not internally_consistent:
        missing.append("consistent_verification_outcomes")

    if not grounding_valid or not internally_consistent or (
        not context.allowed_evidence_ids() and not source_present
    ):
        level = EvidenceSupportLevel.INSUFFICIENT_EVIDENCE
        rationale = (
            "Supporting evidence is missing, internally contradictory, or failed grounding checks."
        )
    elif repro_present and source_present and env_consistent and rev_consistent:
        level = EvidenceSupportLevel.HIGH_EVIDENCE_SUPPORT
        rationale = (
            "Trusted reproduction verification, matching revision/environment, and bounded "
            "source excerpt all support this investigation."
        )
    elif (repro_present and env_consistent and rev_consistent) or (
        source_present and bool(context.allowed_evidence_ids()) and env_consistent
    ):
        level = EvidenceSupportLevel.MODERATE_EVIDENCE_SUPPORT
        rationale = (
            "Consistent supplied evidence supports partial technical analysis, though complete "
            "reproduction or source context has documented gaps."
        )
    else:
        level = EvidenceSupportLevel.LIMITED_EVIDENCE_SUPPORT
        rationale = (
            "Only initial finding/advisory metadata is available without confirmed reproduction "
            "and bounded source confirmation."
        )

    return QualitativeConfidenceAssessment(
        evidence_support_level=level,
        reproduction_evidence_present=repro_present,
        relevant_source_excerpt_present=source_present,
        environment_consistent=env_consistent,
        revision_consistent=rev_consistent,
        evidence_internally_consistent=internally_consistent,
        grounding_valid=grounding_valid,
        missing_conditions=list(dict.fromkeys(missing)),
        rationale=rationale,
    )
