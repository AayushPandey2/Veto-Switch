"""Claim-level evidence grounding engine producing ``GroundingValidationReport`` (Section 17)."""

from __future__ import annotations

from shared.enums import ClaimValidationStatus
from shared.schemas import GroundedClaim, GroundingValidationReport

from agent_core.intelligence.claim_validator import (
    detect_hallucinated_identifiers,
    validate_single_claim,
)
from agent_core.intelligence.investigation_context import InvestigationContext


def validate_investigation_grounding(
    *,
    claims: list[GroundedClaim],
    interpretations: list[GroundedClaim],
    top_level_evidence_ids: list[str],
    executive_summary: str,
    technical_explanation: str,
    affected_components: list[str],
    affected_route: str | None,
    context: InvestigationContext,
) -> tuple[list[GroundedClaim], list[GroundedClaim], GroundingValidationReport]:
    """Validate all claims and top-level references against bounded ``InvestigationContext``."""
    allowed_ids = context.allowed_evidence_ids()
    excluded_reasons = context.excluded_ids_by_reason()

    validated_facts: list[GroundedClaim] = []
    validated_interps: list[GroundedClaim] = []
    unknown_refs: list[str] = []
    unsupported_observed: list[str] = []
    contradictions: list[str] = []
    hallucinated: list[str] = []
    review_claims: list[str] = []
    claims_with_refs = 0

    for eid in top_level_evidence_ids:
        if eid not in allowed_ids:
            reason = excluded_reasons.get(eid)
            suffix = f" ({reason})" if reason else ""
            unknown_refs.append(f"{eid}{suffix}")

    for claim in claims:
        upd, unk, unsup, contra, hall = validate_single_claim(claim, context=context)
        validated_facts.append(upd)
        if claim.evidence_ids:
            claims_with_refs += 1
        unknown_refs.extend(unk)
        unsupported_observed.extend(unsup)
        contradictions.extend(contra)
        hallucinated.extend(hall)
        if upd.validation_status != ClaimValidationStatus.VALIDATED:
            review_claims.append(upd.claim_id)

    for interp in interpretations:
        upd, unk, unsup, contra, hall = validate_single_claim(interp, context=context)
        validated_interps.append(upd)
        if interp.evidence_ids:
            claims_with_refs += 1
        unknown_refs.extend(unk)
        unsupported_observed.extend(unsup)
        contradictions.extend(contra)
        hallucinated.extend(hall)
        review_claims.append(upd.claim_id)

    # Scan prose summaries for fabricated CVEs/file paths
    hallucinated.extend(detect_hallucinated_identifiers(executive_summary, context=context))
    hallucinated.extend(detect_hallucinated_identifiers(technical_explanation, context=context))

    # Reject completely invented component names when we know the target component
    expected_comp = context.affected_component.lower()
    for comp in affected_components:
        comp_low = comp.lower()
        if comp_low != expected_comp and expected_comp not in comp_low and not any(
            d.dependency_name.lower() == comp_low for d in context.dependency_metadata
        ):
            hallucinated.append(f"unrecognized_component:{comp}")

    if affected_route and context.affected_route and affected_route != context.affected_route:
        contradictions.append(
            f"affected_route mismatch: reported {affected_route!r}, "
            f"authoritative finding specifies {context.affected_route!r}."
        )

    dedup_unknown = list(dict.fromkeys(unknown_refs))
    dedup_unsup = list(dict.fromkeys(unsupported_observed))
    dedup_contra = list(dict.fromkeys(contradictions))
    dedup_hall = list(dict.fromkeys(hallucinated))
    dedup_review = list(dict.fromkeys(review_claims))

    ref_checks_passed = not dedup_unknown and not dedup_unsup
    contra_checks_passed = not dedup_contra and not dedup_hall
    semantic_review_required = bool(
        validated_interps or not contra_checks_passed or not ref_checks_passed
    )
    overall_valid = ref_checks_passed and contra_checks_passed

    notes = [
        (
            "Reference and deterministic contradiction checks evaluate structural provenance and "
            "explicit facts only."
        ),
        (
            "Open-ended technical interpretations are never universally proven by deterministic "
            "validators."
        ),
    ]
    if dedup_unknown:
        notes.append(f"Rejected {len(dedup_unknown)} unknown/excluded evidence reference(s).")
    if dedup_contra:
        notes.append(f"Detected {len(dedup_contra)} deterministic factual contradiction(s).")

    report = GroundingValidationReport(
        total_claims=len(claims) + len(interpretations),
        claims_with_supplied_references=claims_with_refs,
        unknown_references=dedup_unknown,
        direct_factual_contradictions=dedup_contra,
        unsupported_observed_claims=dedup_unsup,
        hallucinated_identifiers=dedup_hall,
        claims_requiring_review=dedup_review,
        missing_evidence=list(context.missing_information),
        reference_checks_passed=ref_checks_passed,
        contradiction_checks_passed=contra_checks_passed,
        semantic_review_required=semantic_review_required,
        overall_valid=overall_valid,
        notes=notes,
    )
    return validated_facts, validated_interps, report
