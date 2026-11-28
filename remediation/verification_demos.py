"""Offline Phase 08 isolated patch verification demonstrations (Demos A-J)."""

from __future__ import annotations

import asyncio
from typing import Any

from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    PatchOrigin,
    PatchStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import utc_now
from shared.schemas import Finding, PatchProposal

from remediation.adapters.fixture_runner import FixturePatchTestRunner, FixtureScenario
from remediation.patch_tests import IsolatedPatchVerificationOrchestrator
from remediation.patching.diff_validator import compute_candidate_hash
from remediation.patching.source_access import PLATFORM_DEMO_TARGET, STAND_IN_TARGET
from remediation.verification.dashboard import (
    render_verification_markdown,
    serialize_verification_dashboard,
)
from remediation.verification.models import PatchVerificationContext, PatchVerificationReport

_SAMPLE_DIFF = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -10,1 +10,1 @@\n"
    '-    cursor.execute(f"SELECT * FROM items WHERE name LIKE %{q}%")\n'
    '+    cursor.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{q}%",))'
)


def _sample_finding() -> Finding:
    return Finding(
        finding_id="fnd_00000000000000000000000000000801",
        incident_id="inc_00000000000000000000000000000801",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        status=FindingStatus.REPRODUCED,
        affected_component="app.py",
        affected_route="/search",
        repository_revision="rev_standin_001",
        environment="demo-staging",
        evidence_ids=["art_00000000000000000000000000000800"],
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )


def _sample_proposal(*, override_hash: str | None = None) -> PatchProposal:
    return PatchProposal(
        patch_id="pat_00000000000000000000000000000801",
        incident_id="inc_00000000000000000000000000000801",
        finding_id="fnd_00000000000000000000000000000801",
        source_revision="rev_standin_001",
        candidate_artifact_id="art_00000000000000000000000000000801",
        candidate_content_hash=override_hash or compute_candidate_hash(_SAMPLE_DIFF),
        unified_diff=_SAMPLE_DIFF,
        allowed_files=["app.py"],
        touched_files=["app.py"],
        technical_rationale="Use parameterized SQLite placeholder instead of f-string.",
        expected_behavior_changes=["Search query parameters are bound safely."],
        required_tests=[
            "sqli_search_exploit",
            "func_search_normal",
            "negative_search_empty",
            "smoke_health",
        ],
        potential_regressions=["Empty search input edge case."],
        assumptions=["SQLite DBAPI ? placeholder applies."],
        patch_origin=PatchOrigin.REFERENCE_FIXTURE,
        status=PatchStatus.PATCH_PROPOSED,
        review_required=True,
        created_at=utc_now(),
    )


def _base_context(
    *,
    source_target: str = STAND_IN_TARGET.target_id,
    missing_smoke: bool = False,
    override_hash: str | None = None,
) -> PatchVerificationContext:
    smoke = [] if missing_smoke else ["smoke_health"]
    return PatchVerificationContext(
        incident_id="inc_00000000000000000000000000000801",
        finding=_sample_finding(),
        proposal=_sample_proposal(override_hash=override_hash),
        source_target=source_target,
        authoritative_base_revision="rev_standin_001",
        required_security_tests=["sqli_search_exploit"],
        required_functional_tests=["func_search_normal"],
        required_negative_input_tests=["negative_search_empty"],
        required_smoke_tests=smoke,
        fixture_mode=True,
        allowed_files=["app.py"],
    )


async def run_all_verification_demos() -> dict[str, PatchVerificationReport]:
    """Execute offline Demos A through J and return their reports."""
    specs: list[tuple[str, PatchVerificationContext, FixtureScenario]] = [
        ("demo_a_verified_pass", _base_context(), "pass"),
        ("demo_b_security_fail", _base_context(), "security_fail"),
        ("demo_c_functional_fail", _base_context(), "functional_fail"),
        ("demo_d_smoke_fail", _base_context(), "smoke_fail"),
        ("demo_e_missing_mandatory_tests", _base_context(missing_smoke=True), "pass"),
        ("demo_f_runtime_revision_missing", _base_context(), "runtime_revision_missing"),
        (
            "demo_g_candidate_hash_mismatch",
            _base_context(override_hash="f" * 64),
            "pass",
        ),
        (
            "demo_h_unsupported_target",
            _base_context(source_target=PLATFORM_DEMO_TARGET.target_id),
            "pass",
        ),
        ("demo_i_timeout_outcome_unknown", _base_context(), "timeout_outcome_unknown"),
        ("demo_j_insufficient_isolation", _base_context(), "insufficient_isolation"),
    ]
    reports: dict[str, PatchVerificationReport] = {}
    for name, ctx, scenario in specs:
        orch = IsolatedPatchVerificationOrchestrator(
            runner=FixturePatchTestRunner(scenario=scenario, source_target=ctx.source_target)
        )
        reports[name] = await orch.verify_candidate(ctx)
    return reports


def main() -> None:
    reports = asyncio.run(run_all_verification_demos())
    for name, report in reports.items():
        dash: dict[str, Any] = serialize_verification_dashboard(report)
        print(
            f"[{name}] accepted={dash['accepted']} status={dash['overall_status']} "
            f"reasons={dash['reason_codes']}"
        )
    print("\n--- Demo A Markdown Summary ---")
    print(render_verification_markdown(reports["demo_a_verified_pass"]))


if __name__ == "__main__":
    main()
