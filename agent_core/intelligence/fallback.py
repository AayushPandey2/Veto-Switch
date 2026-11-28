"""Category-specific deterministic fallback intelligence (Section 21).

Operates strictly from trusted normalized inputs without calling any external LLM.
Never invents root-cause source statements or upgrades suspected findings.
"""

from __future__ import annotations

from shared.enums import (
    ClaimCategory,
    ClaimValidationStatus,
    EvidenceProvenance,
    FindingStatus,
    InvestigationStatus,
    VulnerabilityCategory,
)
from shared.identifiers import generate_investigation_id, utc_now
from shared.schemas import (
    GroundedClaim,
    GroundingValidationReport,
    InvestigationSummary,
    ModelMetadata,
    PotentialImpact,
)

from agent_core.intelligence.investigation_context import InvestigationContext
from agent_core.intelligence.uncertainty import evaluate_uncertainty

FALLBACK_POLICY_VERSION = "1.0.0"

_CATEGORY_POTENTIAL_RISKS: dict[VulnerabilityCategory, str] = {
    VulnerabilityCategory.SQL_INJECTION: (
        "Potential unauthorized database query manipulation or data exposure if input reaches "
        "unparameterized SQL execution."
    ),
    VulnerabilityCategory.PATH_TRAVERSAL: (
        "Potential unauthorized filesystem read outside allowed root directories if path "
        "normalization and containment checks are bypassed."
    ),
    VulnerabilityCategory.DEPENDENCY_CVE: (
        "Potential inherited vulnerability exposure if the affected dependency API is reachable "
        "under active runtime configuration."
    ),
    VulnerabilityCategory.OTHER: (
        "Potential security exposure requiring domain-specific human technical triage."
    ),
}


class DeterministicFallbackInvestigator:
    """Builds transparent, bounded summaries cleanly labeled ``DETERMINISTIC_FALLBACK``."""

    def build_fallback(
        self,
        *,
        context: InvestigationContext,
        fallback_reason: str,
        original_provider: str | None = None,
        original_model: str | None = None,
        prompt_version: str | None = None,
        prompt_hash: str | None = None,
        has_untrusted_anomalies: bool = False,
    ) -> tuple[InvestigationSummary, GroundingValidationReport]:
        finding = context.finding
        allowed_ids = sorted(context.allowed_evidence_ids())
        has_source = bool(context.bounded_source_excerpts)
        repro_confirmed = (
            finding.status == FindingStatus.REPRODUCED
            and context.verification_summary.reproduction_outcome == "reproduced"
        )

        facts: list[GroundedClaim] = []
        primary_ref = allowed_ids[:1]
        if primary_ref:
            facts.append(
                GroundedClaim(
                    claim_id="clm_fb_001",
                    statement=(
                        f"Normalized {finding.category.value} finding {finding.finding_id} "
                        f"for component {finding.affected_component!r} carries authoritative "
                        f"status={finding.status.value!r}."
                    ),
                    classification=ClaimCategory.OBSERVED,
                    evidence_ids=primary_ref,
                    environment=context.environment,
                    source_revision=context.repository_revision,
                    validation_status=ClaimValidationStatus.VALIDATED,
                    limitations=[],
                )
            )

        if repro_confirmed and allowed_ids:
            repro_refs = context.verification_summary.artifact_references or primary_ref
            facts.append(
                GroundedClaim(
                    claim_id="clm_fb_002",
                    statement=(
                        "Authorized security verification confirmed vulnerability reproduction "
                        f"in environment {context.environment or 'unknown'!r}."
                    ),
                    classification=ClaimCategory.OBSERVED,
                    evidence_ids=repro_refs[:2],
                    environment=context.environment,
                    source_revision=context.repository_revision,
                    validation_status=ClaimValidationStatus.VALIDATED,
                    limitations=[],
                )
            )

        # Category-aware technical explanation without fabricating absent root-cause details
        route_phrase = f" on route {finding.affected_route!r}" if finding.affected_route else ""
        if has_source:
            source_note = (
                f"{len(context.bounded_source_excerpts)} bounded source excerpt(s) were supplied "
                "and preserved for deterministic review; LLM semantic analysis was unavailable."
            )
        else:
            source_note = (
                "No authorized source-code excerpt was supplied; exact vulnerable code statements "
                "cannot be confirmed."
            )

        if finding.category == VulnerabilityCategory.DEPENDENCY_CVE:
            cve_str = ", ".join(finding.cve_ids) if finding.cve_ids else "unspecified CVE"
            tech_expl = (
                f"[DETERMINISTIC FALLBACK policy={FALLBACK_POLICY_VERSION}] Recorded dependency "
                f"finding ({cve_str}) for {finding.affected_component!r}. An advisory match "
                "does not independently prove runtime reachability or reproduction. " + source_note
            )
        else:
            tech_expl = (
                f"[DETERMINISTIC FALLBACK policy={FALLBACK_POLICY_VERSION}] Recorded "
                f"{finding.category.value} finding for component {finding.affected_component!r}"
                f"{route_phrase} (status={finding.status.value}). " + source_note
            )

        uncertainties: list[str] = [
            f"Deterministic fallback activated ({fallback_reason}); LLM semantic analysis "
            "was not used.",
            "Broader application impact outside supplied evidence has not been evaluated.",
        ]
        if not has_source:
            uncertainties.append(
                "Source-level root cause cannot be named without an authorized source excerpt."
            )
        if not repro_confirmed:
            uncertainties.append(
                "Vulnerability exploitation has not been reproduced by verification."
            )

        grounding = GroundingValidationReport(
            total_claims=len(facts),
            claims_with_supplied_references=sum(1 for f in facts if f.evidence_ids),
            unknown_references=[],
            direct_factual_contradictions=[],
            unsupported_observed_claims=[],
            hallucinated_identifiers=[],
            claims_requiring_review=[],
            missing_evidence=list(context.missing_information),
            reference_checks_passed=True,
            contradiction_checks_passed=True,
            semantic_review_required=bool(
                not repro_confirmed
                or finding.category == VulnerabilityCategory.OTHER
                or context.verification_summary.conflicting_outcomes
                or has_untrusted_anomalies
            ),
            overall_valid=True,
            notes=[
                f"Produced deterministically under fallback policy {FALLBACK_POLICY_VERSION}."
            ],
        )

        uncertainty = evaluate_uncertainty(
            context=context,
            grounding_report=grounding,
            model_uncertainties=uncertainties,
            model_missing=context.missing_information,
            has_untrusted_anomalies=has_untrusted_anomalies,
        )

        if (
            uncertainty.requires_manual_review
            or finding.category == VulnerabilityCategory.OTHER
            or context.verification_summary.conflicting_outcomes
        ):
            next_action = "require_manual_review"
            inv_status = InvestigationStatus.MANUAL_REVIEW_REQUIRED
        elif repro_confirmed and allowed_ids:
            next_action = "request_feature_mapping"
            inv_status = (
                InvestigationStatus.PARTIAL if not has_source else uncertainty.investigation_status
            )
        elif finding.status == FindingStatus.SUSPECTED:
            next_action = "request_verification"
            inv_status = (
                InvestigationStatus.INSUFFICIENT_EVIDENCE
                if not allowed_ids
                else InvestigationStatus.PARTIAL
            )
        else:
            next_action = "request_more_evidence"
            inv_status = InvestigationStatus.INSUFFICIENT_EVIDENCE

        meta = ModelMetadata(
            provider=original_provider or "deterministic_fallback",
            model_name=original_model or f"deterministic_policy_v{FALLBACK_POLICY_VERSION}",
            prompt_version=prompt_version or "fallback_only",
            prompt_hash=prompt_hash,
            context_hash=context.context_hash or None,
            latency_ms=0.0,
            token_usage=None,
            input_tokens=None,
            output_tokens=None,
            fallback_used=True,
            fallback_reason=fallback_reason,
            synthetic_origin=False,
        )

        summary = InvestigationSummary(
            investigation_id=generate_investigation_id(),
            finding_id=finding.finding_id,
            incident_id=finding.incident_id,
            executive_summary=(
                f"[FALLBACK] {finding.category.value} finding in "
                f"{finding.affected_component}{route_phrase} [status={finding.status.value}]."
            ),
            technical_explanation=tech_expl,
            affected_components=[finding.affected_component],
            observed_effects=(
                [finding.observed_impact]
                if repro_confirmed and finding.observed_impact
                else []
            ),
            verified_facts=[c.statement for c in facts],
            assumptions=[],
            uncertainties=uncertainty.uncertainties,
            evidence_ids=allowed_ids,
            recommended_next_action=next_action,
            reasoning_source=EvidenceProvenance.DETERMINISTIC_FALLBACK,
            model_metadata=meta,
            created_at=utc_now(),
            investigation_status=inv_status,
            finding_status=finding.status,
            affected_route=finding.affected_route,
            grounded_facts=facts,
            technical_interpretations=[],
            potential_impacts=[
                PotentialImpact(
                    description=_CATEGORY_POTENTIAL_RISKS[finding.category],
                    verified=repro_confirmed and bool(finding.observed_impact),
                    limitations=["Derived deterministically without LLM semantic analysis."],
                )
            ],
            missing_evidence=uncertainty.missing_evidence,
            requires_manual_review=bool(
                uncertainty.requires_manual_review or next_action == "require_manual_review"
            ),
            evidence_support_level=uncertainty.confidence_assessment.evidence_support_level,
            prompt_version=prompt_version,
            prompt_hash=prompt_hash,
            context_hash=context.context_hash or None,
            fallback_used=True,
            fallback_reason=fallback_reason,
            grounding_report=grounding,
        )
        return summary, grounding
