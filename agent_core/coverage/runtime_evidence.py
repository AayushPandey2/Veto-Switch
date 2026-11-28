"""Runtime corroboration and identity-scope assessment for coverage auditing."""

from __future__ import annotations

from collections.abc import Sequence

from shared.enums import CoverageEvidenceSupport, CoverageStatus, VerificationPhase
from shared.schemas import FeatureState, VerificationResult

from agent_core.coverage.models import ExecutionPathAssessment, RuntimeCorroborationSummary


def corroborate_with_runtime_evidence(
    *,
    assessments: Sequence[ExecutionPathAssessment],
    observed_features: Sequence[FeatureState],
    verification_results: Sequence[VerificationResult],
    environment: str,
    is_fixture: bool,
) -> RuntimeCorroborationSummary:
    """Corroborate static coverage findings against trusted FeatureState & VerificationResult."""
    if is_fixture and not observed_features and not verification_results:
        return RuntimeCorroborationSummary(
            evidence_support=CoverageEvidenceSupport.FIXTURE,
            missing_runtime_evidence=["fixture_mode_without_runtime_observations"],
            notes=["Audit ran on isolated static fixture; not live runtime verification."],
        )

    if not observed_features and not verification_results:
        return RuntimeCorroborationSummary(
            evidence_support=CoverageEvidenceSupport.SOURCE_ONLY,
            missing_runtime_evidence=["no_feature_state_or_verification_observations"],
            notes=["Static source audit only; runtime corroboration unavailable."],
        )

    observed_flags = sorted({f.feature_name for f in observed_features})
    identity_scopes = sorted(
        {
            f.environment if f.environment == environment else f"env_mismatch:{f.environment}"
            for f in observed_features
        }
    )

    contradictions: list[str] = []
    notes: list[str] = []

    # Check if any trusted post-containment verification STILL reproduced exploit on a route
    # that static analysis claimed was PROTECTED.
    protected_routes = {
        a.route_identity.route
        for a in assessments
        if a.status == CoverageStatus.PROTECTED
    }
    for ver in verification_results:
        if (
            ver.phase == VerificationPhase.AFTER_CONTAINMENT
            and ver.vulnerability_reproduced is True
        ):
            contradictions.append(
                f"Verification {ver.verification_id} reproduced exploit after containment; "
                f"contradicts unqualified static protection claim for {sorted(protected_routes)}."
            )

    # Check if observed global disabled state is present without identity-level proof.
    if observed_features and any(not f.enabled for f in observed_features):
        notes.append(
            "Global feature-disabled observation does not prove per-identity "
            "Flagsmith overrides are absent."
        )

    if contradictions:
        support = CoverageEvidenceSupport.CONTRADICTED
    elif is_fixture:
        support = CoverageEvidenceSupport.FIXTURE
    else:
        support = CoverageEvidenceSupport.RUNTIME_CORROBORATED

    return RuntimeCorroborationSummary(
        evidence_support=support,
        observed_flags=observed_flags,
        identity_scopes=identity_scopes,
        contradicted=bool(contradictions),
        contradiction_details=contradictions,
        notes=notes,
    )
