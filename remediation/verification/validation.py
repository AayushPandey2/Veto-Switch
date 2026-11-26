"""Deterministic pre-flight, test-plan, revision, isolation, and evidence validators."""

from __future__ import annotations

from shared.enums import (
    EvidenceProvenance,
    PatchVerificationReasonCode,
)
from shared.exceptions import PatchValidationError
from shared.schemas import ArtifactReference, PatchTestResult

from remediation.patching.diff_validator import (
    compute_candidate_hash,
    parse_unified_diff,
)
from remediation.patching.models import PatchLimitsConfig
from remediation.patching.source_access import (
    PLATFORM_DEMO_TARGET,
    REGISTERED_PATCH_TARGETS,
    STAND_IN_TARGET,
)
from remediation.verification.models import (
    IsolationPolicy,
    ObservedIsolationMetadata,
    PatchVerificationContext,
    RevisionVerification,
    TestPlanCompleteness,
)


def validate_source_target_compatibility(
    source_target: str,
) -> tuple[bool, list[PatchVerificationReasonCode], list[str]]:
    """Verify whether the source target supports isolated patch verification."""
    if source_target == PLATFORM_DEMO_TARGET.target_id:
        return (
            False,
            [PatchVerificationReasonCode.UNSUPPORTED_SOURCE_TARGET],
            [
                f"Source target {source_target!r} does not have an isolated patch sandbox; "
                "verification marked not_run rather than substituting stand_in."
            ],
        )
    if (
        source_target not in REGISTERED_PATCH_TARGETS
        or source_target != STAND_IN_TARGET.target_id
    ):
        return (
            False,
            [PatchVerificationReasonCode.UNSUPPORTED_SOURCE_TARGET],
            [f"Source target {source_target!r} is not an authorized isolated patch target."],
        )
    return True, [], []


def validate_candidate_integrity(
    ctx: PatchVerificationContext,
) -> tuple[bool, list[PatchVerificationReasonCode], list[str]]:
    """Independently verify candidate hash, artifact bytes, and diff structural safety."""
    reasons: list[PatchVerificationReasonCode] = []
    notes: list[str] = []

    proposal = ctx.proposal
    if proposal.incident_id != ctx.incident_id:
        reasons.append(PatchVerificationReasonCode.CANDIDATE_VALIDATION_FAILED)
        notes.append("PatchProposal incident_id does not match verification incident_id.")

    if proposal.finding_id != ctx.finding.finding_id:
        reasons.append(PatchVerificationReasonCode.CANDIDATE_VALIDATION_FAILED)
        notes.append("PatchProposal finding_id does not match Finding.")

    expected_hash = compute_candidate_hash(proposal.unified_diff)
    if proposal.candidate_content_hash != expected_hash:
        reasons.append(PatchVerificationReasonCode.CANDIDATE_HASH_MISMATCH)
        notes.append(
            f"Candidate hash mismatch: proposal={proposal.candidate_content_hash} "
            f"computed={expected_hash}."
        )

    if ctx.candidate_diff_bytes is not None:
        raw_normalized = ctx.candidate_diff_bytes.decode("utf-8", errors="replace").replace(
            "\r\n", "\n"
        )
        bytes_hash = compute_candidate_hash(raw_normalized)
        if bytes_hash != proposal.candidate_content_hash:
            reasons.append(PatchVerificationReasonCode.CANDIDATE_HASH_MISMATCH)
            notes.append(
                "Retrieved candidate diff artifact bytes do not match candidate_content_hash."
            )

    if ctx.candidate_artifact is not None:
        if ctx.candidate_artifact.incident_id != ctx.incident_id:
            reasons.append(PatchVerificationReasonCode.EVIDENCE_PROVENANCE_UNTRUSTED)
            notes.append("Candidate artifact belongs to a different incident.")
        if ctx.candidate_artifact.content_hash != proposal.candidate_content_hash:
            reasons.append(PatchVerificationReasonCode.CANDIDATE_HASH_MISMATCH)
            notes.append("Candidate artifact content_hash does not match proposal.")

    allowed = ctx.allowed_files or list(proposal.allowed_files)
    if proposal.source_revision != ctx.authoritative_base_revision:
        reasons.append(PatchVerificationReasonCode.BASE_REVISION_MISMATCH)
        notes.append(
            f"PatchProposal source_revision ({proposal.source_revision}) != "
            f"authoritative ({ctx.authoritative_base_revision})."
        )
    if not set(proposal.touched_files).issubset(set(allowed)):
        reasons.append(PatchVerificationReasonCode.CANDIDATE_VALIDATION_FAILED)
        notes.append("PatchProposal touched_files exceed allowed_files.")
    try:
        parsed = parse_unified_diff(proposal.unified_diff, limits=PatchLimitsConfig())
        if sorted(parsed.actual_touched_files) != sorted(proposal.touched_files):
            reasons.append(PatchVerificationReasonCode.CANDIDATE_VALIDATION_FAILED)
            notes.append("Unified diff touched files do not match proposal.touched_files.")
    except PatchValidationError as exc:
        reasons.append(PatchVerificationReasonCode.CANDIDATE_VALIDATION_FAILED)
        notes.append(str(exc))

    deduped = list(dict.fromkeys(reasons))
    return len(deduped) == 0, deduped, notes


def build_mandatory_test_plan(ctx: PatchVerificationContext) -> list[str]:
    """Build deterministic deduplicated mandatory test list from verification context."""
    ordered = [
        *ctx.required_security_tests,
        *ctx.required_functional_tests,
        *ctx.required_negative_input_tests,
        *ctx.required_smoke_tests,
        *ctx.proposal.required_tests,
    ]
    return list(dict.fromkeys(t for t in ordered if t))


def validate_test_plan_completeness(
    ctx: PatchVerificationContext,
    result: PatchTestResult | None = None,
) -> TestPlanCompleteness:
    """Ensure security, functional, negative-input, and smoke tests are all present and run."""
    reasons: list[PatchVerificationReasonCode] = []
    missing_categories: list[str] = []

    if not ctx.required_security_tests:
        missing_categories.append("security")
        reasons.append(PatchVerificationReasonCode.MISSING_SECURITY_TESTS)
    if not ctx.required_functional_tests:
        missing_categories.append("functional")
        reasons.append(PatchVerificationReasonCode.MISSING_FUNCTIONAL_TESTS)
    if not ctx.required_negative_input_tests:
        missing_categories.append("negative_input")
        reasons.append(PatchVerificationReasonCode.MISSING_FUNCTIONAL_TESTS)
    if not ctx.required_smoke_tests:
        missing_categories.append("smoke")
        reasons.append(PatchVerificationReasonCode.MISSING_SMOKE_TESTS)

    required = build_mandatory_test_plan(ctx)
    unknown: list[str] = []
    if ctx.known_test_ids is not None:
        unknown = [tid for tid in required if tid not in ctx.known_test_ids]
        if unknown:
            reasons.append(PatchVerificationReasonCode.UNKNOWN_TEST_ID)

    executed: list[str] = []
    missing_tests: list[str] = []
    if result is not None:
        outcomes_by_name = {item.test_name: item for item in result.individual_outcomes}
        executed = [item.test_name for item in result.individual_outcomes]
        missing_tests = [tid for tid in required if tid not in outcomes_by_name]
        if missing_tests:
            missing_set = set(missing_tests)
            if any(t in missing_set for t in ctx.required_security_tests):
                reasons.append(PatchVerificationReasonCode.MISSING_SECURITY_TESTS)
            if any(
                t in missing_set
                for t in (*ctx.required_functional_tests, *ctx.required_negative_input_tests)
            ):
                reasons.append(PatchVerificationReasonCode.MISSING_FUNCTIONAL_TESTS)
            if any(t in missing_set for t in ctx.required_smoke_tests):
                reasons.append(PatchVerificationReasonCode.MISSING_SMOKE_TESTS)
            if not any(
                r
                in (
                    PatchVerificationReasonCode.MISSING_SECURITY_TESTS,
                    PatchVerificationReasonCode.MISSING_FUNCTIONAL_TESTS,
                    PatchVerificationReasonCode.MISSING_SMOKE_TESTS,
                )
                for r in reasons
            ):
                reasons.append(PatchVerificationReasonCode.PARTIAL_RESULTS_REJECTED)

    deduped = list(dict.fromkeys(reasons))
    complete = (
        bool(required)
        and not missing_categories
        and not unknown
        and (result is None or not missing_tests)
    )
    return TestPlanCompleteness(
        complete=complete,
        required_test_ids=required,
        executed_test_ids=executed,
        missing_test_ids=missing_tests,
        unknown_test_ids=unknown,
        missing_categories=missing_categories,
        reason_codes=deduped,
    )


def validate_revision_identity(
    ctx: PatchVerificationContext,
    result: PatchTestResult,
) -> RevisionVerification:
    """Verify full 5-point revision identity without treating missing runtime revision as match."""
    mismatches: list[str] = []
    reasons: list[PatchVerificationReasonCode] = []

    if result.tested_candidate_hash != ctx.proposal.candidate_content_hash:
        mismatches.append("tested_candidate_hash does not match proposal candidate_content_hash.")
        reasons.append(PatchVerificationReasonCode.CANDIDATE_HASH_MISMATCH)

    if result.expected_source_revision != ctx.authoritative_base_revision:
        mismatches.append("expected_source_revision does not match authoritative base revision.")
        reasons.append(PatchVerificationReasonCode.BASE_REVISION_MISMATCH)

    if result.tested_source_revision != ctx.authoritative_base_revision:
        mismatches.append("tested_source_revision does not match authoritative base revision.")
        reasons.append(PatchVerificationReasonCode.BASE_REVISION_MISMATCH)

    if (
        result.base_source_revision is not None
        and result.base_source_revision != ctx.authoritative_base_revision
    ):
        mismatches.append("base_source_revision does not match authoritative base revision.")
        reasons.append(PatchVerificationReasonCode.BASE_REVISION_MISMATCH)

    expected_patched = ctx.expected_patched_revision or result.expected_patched_revision
    runner_patched = result.runner_computed_patched_revision
    if expected_patched and runner_patched and expected_patched != runner_patched:
        mismatches.append(
            f"runner_computed_patched_revision ({runner_patched}) != expected ({expected_patched})."
        )
        reasons.append(PatchVerificationReasonCode.PATCHED_REVISION_MISMATCH)

    runtime_rev = result.runtime_observed_revision
    if ctx.isolation_policy.require_runtime_revision_match:
        if not runtime_rev:
            mismatches.append(
                "runtime_observed_revision is missing; cannot prove patched code ran."
            )
            reasons.append(PatchVerificationReasonCode.RUNTIME_REVISION_MISSING)
        else:
            ref_patched = runner_patched or result.tested_source_revision
            if runtime_rev != ref_patched:
                mismatches.append(
                    f"runtime_observed_revision ({runtime_rev}) != "
                    f"expected patched ({ref_patched})."
                )
                reasons.append(PatchVerificationReasonCode.RUNTIME_REVISION_MISMATCH)

    deduped = list(dict.fromkeys(reasons))
    return RevisionVerification(
        consistent=len(deduped) == 0,
        base_source_revision=ctx.authoritative_base_revision,
        candidate_content_hash=ctx.proposal.candidate_content_hash,
        expected_patched_revision=expected_patched,
        runner_computed_patched_revision=runner_patched,
        runtime_observed_revision=runtime_rev,
        mismatches=mismatches,
        reason_codes=deduped,
    )


def validate_isolation_metadata(
    policy: IsolationPolicy,
    metadata: dict[str, object],
    *,
    fixture_mode: bool,
) -> tuple[bool, list[PatchVerificationReasonCode], list[str]]:
    """Enforce mandatory sandbox isolation policy against runner-reported metadata."""
    if not metadata:
        return (
            False,
            [PatchVerificationReasonCode.INSUFFICIENT_ISOLATION],
            ["Runner did not report sandbox isolation metadata."],
        )

    try:
        observed = ObservedIsolationMetadata.model_validate(metadata)
    except Exception as exc:
        return (
            False,
            [PatchVerificationReasonCode.INSUFFICIENT_ISOLATION],
            [f"Malformed sandbox isolation metadata: {exc}"],
        )

    notes: list[str] = []
    if observed.mode == "host":
        notes.append("Direct host execution is strictly prohibited for candidate patch testing.")
    if observed.mode not in policy.allowed_runner_modes and not (
        observed.mode == "local_sandbox" and policy.allow_local_sandbox_fallback
    ):
        notes.append(f"Runner mode {observed.mode!r} is not permitted by isolation policy.")
    if observed.mode == "fixture" and not fixture_mode:
        notes.append("Fixture runner mode cannot satisfy non-fixture isolated verification.")
    if policy.require_ephemeral_sandbox and not observed.ephemeral:
        notes.append("Sandbox was not ephemeral.")
    if policy.require_network_disabled and not observed.network_disabled:
        notes.append("Sandbox did not disable outbound network access.")
    if not observed.healthy:
        notes.append("Sandbox target did not reach healthy state.")

    if notes:
        return False, [PatchVerificationReasonCode.INSUFFICIENT_ISOLATION], notes
    return True, [], []


def validate_evidence_integrity(
    result: PatchTestResult,
    artifacts: list[ArtifactReference],
    *,
    fixture_mode: bool,
) -> tuple[bool, list[PatchVerificationReasonCode], list[str]]:
    """Verify artifact references, provenance, and non-empty sanitized logs."""
    reasons: list[PatchVerificationReasonCode] = []
    notes: list[str] = []

    allowed_provenance = (
        {EvidenceProvenance.SECURITY_TEST_OUTPUT, EvidenceProvenance.REFERENCE_FIXTURE}
        if fixture_mode
        else {EvidenceProvenance.SECURITY_TEST_OUTPUT}
    )
    if result.provenance not in allowed_provenance:
        reasons.append(PatchVerificationReasonCode.EVIDENCE_PROVENANCE_UNTRUSTED)
        notes.append(f"Untrusted PatchTestResult provenance: {result.provenance.value!r}.")

    if not result.artifact_ids:
        reasons.append(PatchVerificationReasonCode.EVIDENCE_MISSING)
        notes.append("PatchTestResult must reference at least one stored evidence artifact.")

    if not result.sanitized_logs.strip():
        reasons.append(PatchVerificationReasonCode.EVIDENCE_MISSING)
        notes.append("PatchTestResult sanitized_logs cannot be empty.")

    art_by_id = {art.artifact_id: art for art in artifacts}
    for aid in result.artifact_ids:
        art = art_by_id.get(aid)
        if art is None:
            reasons.append(PatchVerificationReasonCode.EVIDENCE_MISSING)
            notes.append(f"Missing ArtifactReference for {aid}.")
            continue
        if art.incident_id != result.incident_id:
            reasons.append(PatchVerificationReasonCode.EVIDENCE_PROVENANCE_UNTRUSTED)
            notes.append(f"Artifact {aid} incident_id mismatch.")
        if art.provenance not in allowed_provenance:
            reasons.append(PatchVerificationReasonCode.EVIDENCE_PROVENANCE_UNTRUSTED)
            notes.append(f"Artifact {aid} provenance {art.provenance.value!r} is untrusted.")

    deduped = list(dict.fromkeys(reasons))
    return len(deduped) == 0, deduped, notes
