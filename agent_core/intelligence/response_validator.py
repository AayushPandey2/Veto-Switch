"""Strict investigation output schema and semantic + grounding validation."""

from __future__ import annotations

from typing import Literal

from pydantic import Field
from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    InvestigationStatus,
    VulnerabilityCategory,
)
from shared.exceptions import LLMResponseValidationError
from shared.identifiers import generate_investigation_id, utc_now
from shared.schemas import (
    GroundedClaim,
    GroundingValidationReport,
    InvestigationSummary,
    KillswitchModel,
    ModelMetadata,
    PotentialImpact,
)

from agent_core.intelligence.evidence_grounding import validate_investigation_grounding
from agent_core.intelligence.investigation_context import InvestigationContext
from agent_core.intelligence.uncertainty import UncertaintyAssessment, evaluate_uncertainty

ALLOWED_NEXT_ACTIONS: frozenset[str] = frozenset(
    {
        "request_verification",
        "request_more_evidence",
        "request_feature_mapping",
        "require_manual_review",
    }
)

_FORBIDDEN_AUTH_PHRASES = (
    "execute flagsmith",
    "disable flag now without approval",
    "auto-approved",
    "bypass approval",
    "run shell command",
    "grant admin",
)


class RawInvestigationOutput(KillswitchModel):
    """Strict structured schema requested directly from the LLM via ``LLMGateway``."""

    executive_summary: str = Field(min_length=1, max_length=1200)
    technical_explanation: str = Field(min_length=1, max_length=4000)
    affected_components: list[str] = Field(min_length=1, max_length=15)
    observed_effects: list[str] = Field(default_factory=list, max_length=15)
    grounded_facts: list[GroundedClaim] = Field(default_factory=list, max_length=25)
    technical_interpretations: list[GroundedClaim] = Field(default_factory=list, max_length=25)
    potential_impacts: list[PotentialImpact] = Field(default_factory=list, max_length=15)
    assumptions: list[str] = Field(default_factory=list, max_length=15)
    uncertainties: list[str] = Field(default_factory=list, max_length=15)
    missing_evidence: list[str] = Field(default_factory=list, max_length=15)
    recommended_next_action: Literal[
        "request_verification",
        "request_more_evidence",
        "request_feature_mapping",
        "require_manual_review",
    ]
    evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    model_reported_confidence: str | None = Field(default=None, max_length=120)


def check_raw_investigation_semantics(raw_obj: object) -> list[str]:
    """Fast semantic guardrail callback compatible with ``LLMGateway.generate_structured``."""
    if not isinstance(raw_obj, RawInvestigationOutput):
        return ["Expected RawInvestigationOutput instance."]

    errors: list[str] = []
    if raw_obj.recommended_next_action not in ALLOWED_NEXT_ACTIONS:
        errors.append(f"Unsupported recommended_next_action: {raw_obj.recommended_next_action!r}.")

    combined_text = (raw_obj.executive_summary + "\n" + raw_obj.technical_explanation).lower()
    for phrase in _FORBIDDEN_AUTH_PHRASES:
        if phrase in combined_text:
            errors.append(f"Disallowed operational authorization phrase detected: {phrase!r}.")
    if "%" in (raw_obj.model_reported_confidence or ""):
        errors.append(
            "model_reported_confidence must be qualitative, never a misleading percentage."
        )
    return errors


class InvestigationResponseValidator:
    """Validates LLM structured outputs for identity, safety, grounding, and uncertainty."""

    def validate(
        self,
        *,
        raw_output: RawInvestigationOutput,
        context: InvestigationContext,
        model_metadata: ModelMetadata,
        prompt_version: str,
        prompt_hash: str,
        synthetic_origin: bool = False,
    ) -> tuple[InvestigationSummary, GroundingValidationReport, UncertaintyAssessment]:
        finding = context.finding
        semantic_errors = check_raw_investigation_semantics(raw_output)
        if semantic_errors:
            raise LLMResponseValidationError(
                "Investigation response failed semantic safety validation.",
                context={"errors": semantic_errors},
            )

        # Enforce authoritative next-action rules (cannot recommend mapping for suspected/other)
        recommended_action = raw_output.recommended_next_action
        if (
            finding.status == FindingStatus.SUSPECTED
            or context.verification_summary.reproduction_outcome != "reproduced"
        ) and recommended_action == "request_feature_mapping":
            raise LLMResponseValidationError(
                "Cannot recommend feature mapping without confirmed reproduction verification.",
                context={
                    "finding_status": finding.status.value,
                    "reproduction_outcome": context.verification_summary.reproduction_outcome,
                },
            )

        if (
            finding.category == VulnerabilityCategory.OTHER
            and recommended_action == "request_feature_mapping"
        ):
            raise LLMResponseValidationError(
                "Unsupported category 'other' cannot recommend automatic feature mapping.",
                context={"category": finding.category.value},
            )

        # Unverified potential impact invariant
        normalized_impacts: list[PotentialImpact] = []
        for imp in raw_output.potential_impacts:
            if imp.verified and (
                finding.status != FindingStatus.REPRODUCED
                or context.verification_summary.reproduction_outcome != "reproduced"
            ):
                raise LLMResponseValidationError(
                    "Unverified PotentialImpact cannot set verified=True without reproduction.",
                )
            normalized_impacts.append(imp)

        facts, interps, grounding = validate_investigation_grounding(
            claims=raw_output.grounded_facts,
            interpretations=raw_output.technical_interpretations,
            top_level_evidence_ids=raw_output.evidence_ids,
            executive_summary=raw_output.executive_summary,
            technical_explanation=raw_output.technical_explanation,
            affected_components=raw_output.affected_components,
            affected_route=finding.affected_route,
            context=context,
        )

        if not grounding.overall_valid:
            raise LLMResponseValidationError(
                "Claim-level evidence grounding failed deterministic validation.",
                context={
                    "unknown_references": grounding.unknown_references,
                    "contradictions": grounding.direct_factual_contradictions,
                    "unsupported_observed_claims": grounding.unsupported_observed_claims,
                    "hallucinated_identifiers": grounding.hallucinated_identifiers,
                },
            )

        uncertainty = evaluate_uncertainty(
            context=context,
            grounding_report=grounding,
            model_uncertainties=raw_output.uncertainties,
            model_missing=raw_output.missing_evidence,
            model_reported_confidence=raw_output.model_reported_confidence,
        )

        # Preserve authoritative status — NEVER upgrade suspected to reproduced!
        final_next_action = recommended_action
        if uncertainty.requires_manual_review and final_next_action == "request_feature_mapping":
            final_next_action = "require_manual_review"
            uncertainty = uncertainty.model_copy(
                update={"investigation_status": InvestigationStatus.MANUAL_REVIEW_REQUIRED}
            )

        verified_fact_strings = [f.statement for f in facts]
        allowed_ids = context.allowed_evidence_ids()
        dedup_ev_ids = list(
            dict.fromkeys(eid for eid in raw_output.evidence_ids if eid in allowed_ids)
        )
        reasoning_src = (
            EvidenceProvenance.REFERENCE_FIXTURE
            if synthetic_origin
            else EvidenceProvenance.LLM_INTERPRETATION
        )

        summary = InvestigationSummary(
            investigation_id=generate_investigation_id(),
            finding_id=finding.finding_id,
            incident_id=finding.incident_id,
            executive_summary=raw_output.executive_summary,
            technical_explanation=raw_output.technical_explanation,
            affected_components=list(raw_output.affected_components),
            observed_effects=list(raw_output.observed_effects),
            verified_facts=verified_fact_strings,
            assumptions=list(raw_output.assumptions),
            uncertainties=uncertainty.uncertainties,
            evidence_ids=dedup_ev_ids,
            recommended_next_action=final_next_action,
            reasoning_source=reasoning_src,
            model_metadata=model_metadata,
            created_at=utc_now(),
            investigation_status=uncertainty.investigation_status,
            finding_status=finding.status,
            affected_route=finding.affected_route,
            grounded_facts=facts,
            technical_interpretations=interps,
            potential_impacts=normalized_impacts,
            missing_evidence=uncertainty.missing_evidence,
            requires_manual_review=uncertainty.requires_manual_review,
            evidence_support_level=uncertainty.confidence_assessment.evidence_support_level,
            prompt_version=prompt_version,
            prompt_hash=prompt_hash,
            context_hash=context.context_hash,
            fallback_used=False,
            fallback_reason=None,
            grounding_report=grounding,
        )
        return summary, grounding, uncertainty
