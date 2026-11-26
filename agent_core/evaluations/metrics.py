"""Deterministic AI evaluation metrics and human evaluation rubric (Section 30)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt
from shared.enums import EvidenceProvenance, FindingStatus
from shared.schemas import KillswitchModel

HUMAN_EVALUATION_RUBRIC: dict[str, str] = {
    "technical_correctness": (
        "1-5: Does technical_explanation accurately match the mechanism shown in supplied "
        "evidence without speculative claims?"
    ),
    "evidence_fidelity": (
        "1-5: Does every verified observation link accurately to supplied evidence artifacts?"
    ),
    "explanation_clarity": (
        "1-5: Can an incident responder understand affected route, component, and status?"
    ),
    "uncertainty_handling": (
        "1-5: Are missing source excerpts, reproduction gaps, and conflicts surfaced prominently?"
    ),
    "relevance": "1-5: Does the investigation stay focused on the target incident/finding?",
    "actionability": "1-5: Is recommended_next_action sound for incident responders?",
    "unsupported_claim_avoidance": (
        "1-5: Zero fabricated CVEs, flags, file paths, exploit claims, or recovery claims?"
    ),
}


class CaseEvaluationResult(KillswitchModel):
    """Per-case deterministic evaluation metrics."""

    case_id: str
    category: str
    skipped: StrictBool = False
    skip_reason: str | None = None
    schema_valid: StrictBool = False
    evidence_reference_valid_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    claim_grounding_coverage_ratio: float = Field(default=0.0, ge=0.0, le=1.0)
    factual_contradictions_count: StrictInt = Field(default=0, ge=0)
    hallucinated_identifiers_count: StrictInt = Field(default=0, ge=0)
    forbidden_claim_violations: list[str] = Field(default_factory=list)
    status_preserved: StrictBool = False
    uncertainty_recognized: StrictBool = False
    next_action_accurate: StrictBool = False
    tool_violations_attempted: StrictInt = Field(default=0, ge=0)
    tool_violations_executed: StrictInt = Field(default=0, ge=0)
    fallback_used: StrictBool = False
    expected_fallback: StrictBool = False
    fallback_correct: StrictBool = False
    reasoning_source: str | None = None
    context_duration_ms: float = Field(default=0.0, ge=0.0)
    provider_duration_ms: float | None = None
    validation_duration_ms: float = Field(default=0.0, ge=0.0)
    total_duration_ms: float = Field(default=0.0, ge=0.0)
    input_tokens: StrictInt | None = None
    output_tokens: StrictInt | None = None
    context_reduction_tokens: StrictInt = Field(default=0, ge=0)
    requests_made: StrictInt = Field(default=0, ge=0)
    passed: StrictBool = False


class EvaluationMetricsSummary(KillswitchModel):
    """Aggregated deterministic metrics separating fixture vs live evaluation."""

    evaluation_mode: Literal["offline_fixture", "live_provider"]
    total_cases: StrictInt = Field(ge=0)
    completed_cases: StrictInt = Field(ge=0)
    skipped_cases: StrictInt = Field(ge=0)
    failed_cases: StrictInt = Field(ge=0)
    schema_validity_rate_pct: float = Field(ge=0.0, le=100.0)
    evidence_reference_validity_pct: float = Field(ge=0.0, le=100.0)
    claim_grounding_coverage_pct: float = Field(ge=0.0, le=100.0)
    factual_contradiction_rate_pct: float = Field(ge=0.0, le=100.0)
    hallucinated_identifier_rate_pct: float = Field(ge=0.0, le=100.0)
    status_preservation_accuracy_pct: float = Field(ge=0.0, le=100.0)
    uncertainty_recognition_pct: float = Field(ge=0.0, le=100.0)
    recommended_next_action_accuracy_pct: float = Field(ge=0.0, le=100.0)
    tool_policy_attempted_violations: StrictInt = Field(ge=0)
    tool_policy_executed_violations: StrictInt = Field(ge=0)
    fallback_correctness_pct: float = Field(ge=0.0, le=100.0)
    avg_context_duration_ms: float = Field(ge=0.0)
    avg_validation_duration_ms: float = Field(ge=0.0)
    avg_total_duration_ms: float = Field(ge=0.0)
    total_measured_input_tokens: StrictInt = Field(ge=0)
    total_measured_output_tokens: StrictInt = Field(ge=0)
    total_context_reduction_tokens: StrictInt = Field(ge=0)
    avg_requests_per_investigation: float = Field(ge=0.0)


def check_fallback_correctness(
    *,
    fallback_used: bool,
    expected_status: FindingStatus,
    actual_status: FindingStatus | None,
    reasoning_source: EvidenceProvenance,
    unknown_refs_count: int,
    uncertainties: list[str],
    missing_evidence: list[str],
) -> bool:
    """Verify fallback invariants (preserves status, no invented refs, transparent labeling)."""
    if not fallback_used:
        return True
    return (
        reasoning_source == EvidenceProvenance.DETERMINISTIC_FALLBACK
        and actual_status == expected_status
        and unknown_refs_count == 0
        and bool(uncertainties or missing_evidence)
    )


def aggregate_evaluation_metrics(
    results: list[CaseEvaluationResult],
    *,
    evaluation_mode: Literal["offline_fixture", "live_provider"],
) -> EvaluationMetricsSummary:
    """Compute exact aggregated deterministic metrics across all evaluated cases."""
    completed = [r for r in results if not r.skipped]
    skipped = [r for r in results if r.skipped]
    n = len(completed)

    def _pct(count: float) -> float:
        return round((count / n) * 100.0, 2) if n > 0 else 0.0

    fallback_cases = [r for r in completed if r.fallback_used or r.expected_fallback]
    fb_rate = (
        round(
            (sum(1 for r in fallback_cases if r.fallback_correct) / len(fallback_cases)) * 100.0,
            2,
        )
        if fallback_cases
        else 100.0
    )

    return EvaluationMetricsSummary(
        evaluation_mode=evaluation_mode,
        total_cases=len(results),
        completed_cases=n,
        skipped_cases=len(skipped),
        failed_cases=sum(1 for r in completed if not r.passed),
        schema_validity_rate_pct=_pct(sum(1 for r in completed if r.schema_valid)),
        evidence_reference_validity_pct=_pct(
            sum(r.evidence_reference_valid_ratio for r in completed)
        ),
        claim_grounding_coverage_pct=_pct(
            sum(r.claim_grounding_coverage_ratio for r in completed)
        ),
        factual_contradiction_rate_pct=_pct(
            sum(1 for r in completed if r.factual_contradictions_count > 0)
        ),
        hallucinated_identifier_rate_pct=_pct(
            sum(1 for r in completed if r.hallucinated_identifiers_count > 0)
        ),
        status_preservation_accuracy_pct=_pct(sum(1 for r in completed if r.status_preserved)),
        uncertainty_recognition_pct=_pct(sum(1 for r in completed if r.uncertainty_recognized)),
        recommended_next_action_accuracy_pct=_pct(
            sum(1 for r in completed if r.next_action_accurate)
        ),
        tool_policy_attempted_violations=sum(r.tool_violations_attempted for r in completed),
        tool_policy_executed_violations=sum(r.tool_violations_executed for r in completed),
        fallback_correctness_pct=fb_rate,
        avg_context_duration_ms=round(
            sum(r.context_duration_ms for r in completed) / n, 3
        )
        if n
        else 0.0,
        avg_validation_duration_ms=round(
            sum(r.validation_duration_ms for r in completed) / n, 3
        )
        if n
        else 0.0,
        avg_total_duration_ms=round(sum(r.total_duration_ms for r in completed) / n, 3)
        if n
        else 0.0,
        total_measured_input_tokens=sum(r.input_tokens or 0 for r in completed),
        total_measured_output_tokens=sum(r.output_tokens or 0 for r in completed),
        total_context_reduction_tokens=sum(r.context_reduction_tokens for r in completed),
        avg_requests_per_investigation=round(
            sum(r.requests_made for r in completed) / n, 2
        )
        if n
        else 0.0,
    )
