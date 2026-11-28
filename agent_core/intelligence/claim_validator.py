"""Deterministic factual consistency and hallucinated-identifier checks for claims."""

from __future__ import annotations

import re

from shared.enums import ClaimCategory, ClaimValidationStatus, FindingStatus, VulnerabilityCategory
from shared.schemas import GroundedClaim

from agent_core.intelligence.investigation_context import InvestigationContext

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_FILE_PATH_PATTERN = re.compile(r"\b[a-zA-Z0-9_./\-]+\.(?:py|ts|tsx|js|jsx|sql|go|java|rb|php)\b")

_REPRODUCED_PHRASES = (
    "was reproduced",
    "is reproduced",
    "were reproduced",
    "reproduced the",
    "reproduced against",
    "reproduced unexpected",
    "reproduced vulnerability",
    "confirmed reproduction",
    "reproduction confirmed",
    "exploitation confirmed",
    "exploit confirmed",
    "was exploited",
    "actively exploited",
    "cve was reproduced",
    "cve exploited",
)
_TEST_PASSED_PHRASES = (
    "test passed",
    "tests passed",
    "verification passed",
    "passed all checks",
    "no vulnerability found",
)
_DEPLOYMENT_CLAIMS = (
    "has been deployed",
    "repair has been deployed",
    "patch deployed",
    "incident is contained",
    "is now contained",
    "incident is recovered",
    "fully recovered",
)
_OVERREACH_PHRASES = (
    "all routes are vulnerable",
    "every database route",
    "all endpoints are compromised",
    "entire database is compromised",
    "all files on the server",
)


def detect_hallucinated_identifiers(
    statement: str,
    *,
    context: InvestigationContext,
) -> list[str]:
    """Detect deterministically verifiable fabricated CVE IDs or undeclared file paths."""
    invented: list[str] = []
    allowed_cves = context.allowed_cves()
    for match in _CVE_PATTERN.findall(statement):
        upper_cve = match.upper()
        if upper_cve not in allowed_cves:
            invented.append(f"invented_cve:{upper_cve}")

    allowed_paths = {p.lower() for p in context.allowed_file_paths()}
    for match in _FILE_PATH_PATTERN.findall(statement):
        lowered = match.lower()
        # Allow exact match OR unambiguous suffix match for supplied relative path
        if not any(
            ap == lowered or ap.endswith("/" + lowered) or lowered.endswith("/" + ap)
            for ap in allowed_paths
        ):
            invented.append(f"unverified_file_path:{match}")

    return invented


def detect_factual_contradictions(
    claim: GroundedClaim,
    *,
    context: InvestigationContext,
) -> list[str]:
    """Identify deterministically detectable factual contradictions against supplied context."""
    contradictions: list[str] = []
    lowered = claim.statement.lower()
    outcome = context.verification_summary.reproduction_outcome
    status = context.finding.status

    # 1. Outcome = not_run / infrastructure_error / not_confirmed vs claim test passed
    if outcome in {"not_run", "infrastructure_error", "not_confirmed"} and any(
        phrase in lowered for phrase in _TEST_PASSED_PHRASES
    ):
        contradictions.append(
            f"{claim.claim_id}: claims test passed while verification outcome is {outcome!r}."
        )

    # 2. Contradictory verification outcome claimed as positive confirmation
    if context.verification_summary.conflicting_outcomes and any(
        phrase in lowered for phrase in (*_REPRODUCED_PHRASES, *_TEST_PASSED_PHRASES)
    ):
        contradictions.append(
            f"{claim.claim_id}: claims confirmed outcome despite conflicting verification results."
        )

    # 3. Suspected finding or non-reproduced verification claimed as reproduced/exploited
    if (status == FindingStatus.SUSPECTED or outcome != "reproduced") and any(
        phrase in lowered for phrase in _REPRODUCED_PHRASES
    ):
        contradictions.append(
            f"{claim.claim_id}: claims reproduction/exploitation while finding.status="
            f"{status.value!r} and outcome={outcome!r}."
        )

    # 4. Dependency CVE advisory match without reproduction claiming CVE exploitation
    if (
        context.finding.category == VulnerabilityCategory.DEPENDENCY_CVE
        and outcome != "reproduced"
        and any(p in lowered for p in ("exploitable", "cve exploited", "actively exploited"))
        and "not " not in lowered
        and "does not" not in lowered
        and "if reachable" not in lowered
        and claim.classification == ClaimCategory.OBSERVED
    ):
        contradictions.append(
            f"{claim.claim_id}: claims Dependency CVE exploitability without reproduction proof."
        )

    # 5. Deployment / containment / recovery claim without deployment or containment evidence
    if not context.has_deployment_evidence and not context.has_containment_evidence and any(
        phrase in lowered for phrase in _DEPLOYMENT_CLAIMS
    ):
        contradictions.append(
            f"{claim.claim_id}: claims deployment/containment without supporting evidence."
        )

    # 6. Single-route finding claiming all routes / entire DB affected without evidence
    if context.affected_route and any(phrase in lowered for phrase in _OVERREACH_PHRASES):
        contradictions.append(
            f"{claim.claim_id}: generalizes beyond tested route {context.affected_route!r}."
        )

    return contradictions


def validate_single_claim(
    claim: GroundedClaim,
    *,
    context: InvestigationContext,
) -> tuple[GroundedClaim, list[str], list[str], list[str], list[str]]:
    """Validate one claim against reference existence, scope, contradictions, and identifiers.

    Returns:
        (updated_claim, unknown_refs, unsupported_observed, contradictions, hallucinated_ids)
    """
    allowed_ids = context.allowed_evidence_ids()
    excluded_reasons = context.excluded_ids_by_reason()
    allowed_excerpt_ids = context.allowed_source_excerpt_ids()

    unknown_refs: list[str] = []
    for eid in claim.evidence_ids:
        if eid not in allowed_ids:
            reason = excluded_reasons.get(eid)
            suffix = f" ({reason})" if reason else ""
            unknown_refs.append(f"{eid}{suffix}")

    for src_id in claim.source_excerpt_ids:
        if src_id not in allowed_excerpt_ids:
            reason = excluded_reasons.get(src_id)
            suffix = f" ({reason})" if reason else ""
            unknown_refs.append(f"{src_id}{suffix}")

    env_rev_mismatch: list[str] = []
    if claim.environment and context.environment and claim.environment != context.environment:
        env_rev_mismatch.append(
            f"{claim.claim_id}: claim environment {claim.environment!r} != {context.environment!r}."
        )
    if (
        claim.source_revision
        and context.repository_revision
        and claim.source_revision != context.repository_revision
    ):
        env_rev_mismatch.append(
            f"{claim.claim_id}: claim revision {claim.source_revision!r} != "
            f"{context.repository_revision!r}."
        )

    unsupported_observed: list[str] = []
    if claim.classification == ClaimCategory.OBSERVED and not claim.evidence_ids:
        unsupported_observed.append(claim.claim_id)

    contradictions = detect_factual_contradictions(claim, context=context) + env_rev_mismatch
    hallucinated = detect_hallucinated_identifiers(claim.statement, context=context)

    limitations = list(claim.limitations)
    if unknown_refs:
        status = ClaimValidationStatus.UNSUPPORTED_REFERENCE
        limitations.append("References missing, unverified, or excluded evidence identifiers.")
    elif contradictions or hallucinated:
        status = ClaimValidationStatus.FACTUAL_CONTRADICTION
        limitations.append("Deterministic consistency check detected factual conflict.")
    elif unsupported_observed:
        status = ClaimValidationStatus.UNSUPPORTED_REFERENCE
        limitations.append("Observed claim lacks supporting evidence_ids.")
    elif claim.classification == ClaimCategory.INFERRED:
        status = ClaimValidationStatus.UNVERIFIED_INTERPRETATION
        limitations.append(
            "Technical interpretation involves semantic reasoning beyond deterministic checks."
        )
    else:
        status = ClaimValidationStatus.VALIDATED

    return (
        claim.model_copy(update={"validation_status": status, "limitations": limitations}),
        unknown_refs,
        unsupported_observed,
        contradictions,
        hallucinated,
    )
