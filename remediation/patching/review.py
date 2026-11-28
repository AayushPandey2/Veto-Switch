"""Trusted test-plan builder, reviewer checklist, PR summary, and dashboard serializer."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from shared.enums import VulnerabilityCategory
from shared.schemas import Finding

from remediation.patching.models import (
    PatchGenerationOutcome,
    PatchTargetDescriptor,
    ReviewerChecklist,
    TestPlan,
)


def build_test_plan(
    finding: Finding,
    target: PatchTargetDescriptor,
    *,
    suggested_tests: Sequence[str] = (),
) -> TestPlan:
    """Derive mandatory Phase 08 verification tests from trusted target registry."""
    registered = set(target.registered_test_ids)
    mandatory: list[str] = []
    limitations: list[str] = []

    if finding.category == VulnerabilityCategory.SQL_INJECTION or (
        finding.affected_route in {"/search", "/legacy/search", "/search/"}
    ):
        desired = [
            "sqli_search",
            "functional_search",
            "negative_inputs_search",
            "smoke_status",
            "smoke_catalog",
        ]
    elif finding.category == VulnerabilityCategory.PATH_TRAVERSAL or (
        finding.affected_route in {"/files", "/files/"}
    ):
        desired = [
            "traversal_files",
            "functional_files",
            "negative_inputs_files",
            "smoke_status",
            "smoke_catalog",
        ]
    else:
        desired = ["smoke_status", "smoke_catalog"]

    for tid in desired:
        if tid in registered:
            mandatory.append(tid)
        else:
            limitations.append(
                f"Required test {tid!r} is not registered on target {target.target_id!r}."
            )

    if not target.sandbox_supported:
        limitations.append(
            f"Target {target.target_id!r} is not registered with the isolated security sandbox."
        )

    optional_reg = sorted(
        t for t in suggested_tests if t in registered and t not in mandatory
    )
    unimpl = sorted(t for t in suggested_tests if t not in registered)

    return TestPlan(
        mandatory_registered_tests=mandatory,
        optional_registered_tests=optional_reg,
        suggested_unimplemented_tests=unimpl,
        limitations=limitations,
    )


def build_reviewer_checklist(
    *,
    target: PatchTargetDescriptor,
    test_plan: TestPlan,
) -> ReviewerChecklist:
    """Generate structured 5-section human-review checklist for a candidate patch."""
    return ReviewerChecklist(
        security_review=[
            "Does the patch address the verified source-level cause?",
            "Does it preserve existing authorization and data-visibility rules?",
            "Does it preserve existing feature-flag controls?",
            "Does it introduce no new risky operations or dependencies?",
        ],
        functional_review=[
            "Are legitimate requests expected to continue working?",
            "Are API response contracts preserved?",
            "Are invalid/empty inputs handled cleanly without 500 errors?",
            "Are unrelated services unaffected by the proposed code change?",
        ],
        source_review=[
            f"Is target ({target.target_id}) and revision ({target.source_revision}) exact?",
            f"Are all touched files strictly within allowlist {target.allowed_files}?",
            "Is the unified diff minimal and free of unrelated formatting/logic edits?",
        ],
        verification_review=[
            f"Mandatory tests queued for Phase 08: {test_plan.mandatory_registered_tests}",
            "Confirm security regression, functional, negative-input, and smoke tests run.",
        ],
        recovery_review=[
            "Candidate has NOT been tested in isolated sandbox yet (Phase 08 pending).",
            "Deployment NOT established; separate human authorization required before rollout.",
        ],
    )


def build_pr_summary_markdown(
    *,
    finding: Finding,
    target: PatchTargetDescriptor,
    test_plan: TestPlan,
    checklist: ReviewerChecklist,
    unified_diff: str,
    technical_rationale: str,
    touched_files: Sequence[str],
    candidate_content_hash: str,
    patch_origin: str,
    expected_behavior_changes: Sequence[str],
    potential_regressions: Sequence[str],
    limitations: Sequence[str],
) -> str:
    """Generate a deterministic PR-ready Markdown summary without creating a remote PR."""
    lines = [
        f"# Candidate Remediation Patch: {finding.category.value} ({target.target_id})",
        "",
        "> **Status:** Candidate proposed. Isolated verification pending. "
        "Deployment not established. Feature activation not authorized.",
        "",
        f"- **Incident:** `{finding.incident_id}`",
        f"- **Finding:** `{finding.finding_id}` (`{finding.status.value}`)",
        f"- **Target Application:** `{target.application_id}` (`{target.target_id}`)",
        f"- **Base Source Revision:** `{target.source_revision}` (`{target.revision_namespace}`)",
        f"- **Candidate Origin:** `{patch_origin}`",
        f"- **Candidate SHA-256:** `{candidate_content_hash}`",
        "",
        "## Root-Cause Explanation & Rationale",
        technical_rationale,
        "",
        "## Proposed Change",
        f"Touched files: {', '.join(f'`{f}`' for f in touched_files)}",
        "",
        "```diff",
        unified_diff.rstrip(),
        "```",
        "",
        "## Expected Behavior Changes",
        *([f"- {item}" for item in expected_behavior_changes] or ["- Preserves normal contract."]),
        "",
        "## Potential Regressions",
        *(
            [f"- {item}" for item in potential_regressions]
            or ["- Requires Phase 08 functional & smoke tests."]
        ),
        "",
        "## Required Verification Tests",
        *(
            [f"- `{t}`" for t in test_plan.mandatory_registered_tests]
            or ["- Manual test plan required."]
        ),
        "",
        "## Reviewer Checklist",
        *[f"- [ ] {item}" for item in checklist.security_review],
        *[f"- [ ] {item}" for item in checklist.source_review],
        *[f"- [ ] {item}" for item in checklist.recovery_review],
        "",
        "## Known Limitations",
        *([f"- {lim}" for lim in limitations] or ["- Isolated verification pending."]),
    ]
    return "\n".join(lines) + "\n"


def serialize_patch_dashboard(
    outcome: PatchGenerationOutcome,
    target: PatchTargetDescriptor,
) -> dict[str, Any]:
    """Serialize ``PatchGenerationOutcome`` into deterministic dashboard-compatible JSON."""
    prop = outcome.proposal
    if prop is None:
        return {
            "accepted": False,
            "source_target": target.target_id,
            "source_revision": target.source_revision,
            "sandbox_ready": False,
            "manual_review_required": outcome.manual_review_required,
            "rejection_reasons": [r.value for r in outcome.rejection_reasons],
            "limitations": list(outcome.limitations),
        }

    return {
        "patch_id": prop.patch_id,
        "incident_id": prop.incident_id,
        "finding_id": prop.finding_id,
        "source_target": target.target_id,
        "source_revision": prop.source_revision,
        "patch_status": prop.status.value,
        "patch_origin": prop.patch_origin.value,
        "candidate_content_hash": prop.candidate_content_hash,
        "candidate_artifact_id": prop.candidate_artifact_id,
        "candidate_manifest_fingerprint": outcome.candidate_manifest_fingerprint,
        "touched_files": list(prop.touched_files),
        "validation": {
            "diff_format_valid": True,
            "source_revision_matches": True,
            "file_allowlist_valid": True,
            "candidate_hash_verified": True,
        },
        "minimality": outcome.minimality.model_dump(mode="json") if outcome.minimality else None,
        "technical_rationale": prop.technical_rationale,
        "expected_behavior_changes": list(prop.expected_behavior_changes),
        "potential_regressions": list(prop.potential_regressions),
        "required_tests": list(prop.required_tests),
        "reviewer_checklist": (
            outcome.checklist.model_dump(mode="json") if outcome.checklist else None
        ),
        "review_required": prop.review_required,
        "sandbox_ready": outcome.sandbox_ready,
        "verification": {"status": "not_run"},
        "deployment_verified": False,
        "feature_activation_authorized": False,
        "limitations": list(outcome.limitations),
    }
