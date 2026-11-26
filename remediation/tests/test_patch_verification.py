"""Comprehensive unit & adapter tests for Phase 08 isolated patch verification."""

from __future__ import annotations

import json

import httpx
import pytest
from remediation.adapters.fixture_runner import FixturePatchTestRunner
from remediation.adapters.security_runner import SecurityServicePatchRunner
from remediation.evaluations.patch_verification_evaluator import (
    evaluate_patch_verification_cases,
)
from remediation.patch_tests import IsolatedPatchVerificationOrchestrator, verify_patch
from remediation.patching.source_access import PLATFORM_DEMO_TARGET, STAND_IN_TARGET
from remediation.verification.dashboard import (
    render_verification_markdown,
    serialize_verification_dashboard,
)
from remediation.verification_demos import _base_context, run_all_verification_demos
from shared.enums import (
    PatchVerificationReasonCode,
    TestExecutionStatus,
    VerificationPhase,
)


@pytest.mark.asyncio
async def test_full_isolated_pass_produces_recovery_handoff() -> None:
    ctx = _base_context()
    orch = IsolatedPatchVerificationOrchestrator(
        runner=FixturePatchTestRunner(scenario="pass", source_target=STAND_IN_TARGET.target_id)
    )
    report = await orch.verify_candidate(ctx)

    assert report.candidate_tested is True
    assert report.decision.accepted is True
    assert report.decision.overall_status == TestExecutionStatus.TEST_PASSED
    assert report.decision.reason_codes == [
        PatchVerificationReasonCode.VERIFIED_READY_FOR_DEPLOYMENT
    ]
    handoff = report.decision.recovery_handoff
    assert handoff is not None
    assert handoff.candidate_tested is True
    assert handoff.ready_for_deployment_verification is True
    assert handoff.deployment_verified is False
    assert handoff.rollout_authorized is False

    dash = serialize_verification_dashboard(report)
    assert dash["accepted"] is True
    assert dash["recovery_handoff"]["rollout_authorized"] is False
    md = render_verification_markdown(report)
    assert "Phase 09 Recovery Handoff" in md


@pytest.mark.asyncio
async def test_unsupported_platform_demo_app_returns_not_run() -> None:
    ctx = _base_context(source_target=PLATFORM_DEMO_TARGET.target_id)
    orch = IsolatedPatchVerificationOrchestrator(
        runner=FixturePatchTestRunner(
            scenario="pass", source_target=PLATFORM_DEMO_TARGET.target_id
        )
    )
    report = await orch.verify_candidate(ctx)

    assert report.candidate_tested is False
    assert report.decision.accepted is False
    assert report.decision.overall_status == TestExecutionStatus.NOT_RUN
    assert PatchVerificationReasonCode.UNSUPPORTED_SOURCE_TARGET in report.decision.reason_codes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected_reason", "expected_status"),
    [
        (
            "security_fail",
            PatchVerificationReasonCode.SECURITY_REGRESSION_FAILED,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "functional_fail",
            PatchVerificationReasonCode.FUNCTIONAL_REGRESSION_FAILED,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "smoke_fail",
            PatchVerificationReasonCode.SMOKE_TEST_FAILED,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "missing_tests",
            PatchVerificationReasonCode.MISSING_SMOKE_TESTS,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "base_revision_mismatch",
            PatchVerificationReasonCode.BASE_REVISION_MISMATCH,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "patched_revision_mismatch",
            PatchVerificationReasonCode.PATCHED_REVISION_MISMATCH,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "runtime_revision_mismatch",
            PatchVerificationReasonCode.RUNTIME_REVISION_MISMATCH,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "runtime_revision_missing",
            PatchVerificationReasonCode.RUNTIME_REVISION_MISSING,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "hash_mismatch",
            PatchVerificationReasonCode.CANDIDATE_HASH_MISMATCH,
            TestExecutionStatus.TEST_FAILED,
        ),
        (
            "timeout_outcome_unknown",
            PatchVerificationReasonCode.RUNNER_INFRASTRUCTURE_ERROR,
            TestExecutionStatus.INFRASTRUCTURE_ERROR,
        ),
        (
            "insufficient_isolation",
            PatchVerificationReasonCode.INSUFFICIENT_ISOLATION,
            TestExecutionStatus.INFRASTRUCTURE_ERROR,
        ),
        (
            "artifact_corrupted",
            PatchVerificationReasonCode.EVIDENCE_PROVENANCE_UNTRUSTED,
            TestExecutionStatus.INFRASTRUCTURE_ERROR,
        ),
    ],
)
async def test_fixture_failure_modes_never_false_pass(
    scenario: str,
    expected_reason: PatchVerificationReasonCode,
    expected_status: TestExecutionStatus,
) -> None:
    ctx = _base_context()
    orch = IsolatedPatchVerificationOrchestrator(
        runner=FixturePatchTestRunner(scenario=scenario, source_target=STAND_IN_TARGET.target_id)  # type: ignore[arg-type]
    )
    report = await orch.verify_candidate(ctx)

    assert report.decision.accepted is False
    assert report.decision.overall_status == expected_status
    assert expected_reason in report.decision.reason_codes
    assert report.decision.recovery_handoff is None
    assert report.decision.failure_feedback is not None


@pytest.mark.asyncio
async def test_verify_patch_returns_canonical_after_patch_verification_result() -> None:
    ctx = _base_context()
    ver = await verify_patch(
        ctx.proposal.patch_id,
        "sandbox://stand_in",
        ctx=ctx,
        runner=FixturePatchTestRunner(scenario="pass", source_target=STAND_IN_TARGET.target_id),
    )
    assert ver.phase == VerificationPhase.AFTER_PATCH
    assert ver.execution_status == TestExecutionStatus.TEST_PASSED
    assert ver.passed is True


@pytest.mark.asyncio
async def test_security_service_http_adapter_with_mock_transport() -> None:
    ctx = _base_context()
    secret_token = "ksx-super-secret-token-value"
    seen_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/patches":
            seen_headers.append(request.headers.get("X-KSX-Token"))
            body = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                json={
                    "patch_id": body["patch_id"],
                    "incident_id": body["incident_id"],
                    "base_revision": body["base_revision"],
                    "diff_sha256": ctx.proposal.candidate_content_hash,
                    "source": body["source"],
                },
            )
        if request.url.path == "/patch-tests":
            seen_headers.append(request.headers.get("X-KSX-Token"))
            body = json.loads(request.content.decode("utf-8"))
            patched_rev = "rev_patched_123"
            return httpx.Response(
                200,
                json={
                    "report": {
                        "patch_id": body["patch_id"],
                        "incident_id": ctx.incident_id,
                        "base_revision": ctx.authoritative_base_revision,
                        "patched_revision": patched_rev,
                        "diff_sha256": ctx.proposal.candidate_content_hash,
                        "status": "passed",
                        "evidence_id": "art_00000000000000000000000000000888",
                        "artifact_path": "artifacts/inc/patchtest.json",
                        "sandbox": {
                            "mode": "docker",
                            "ephemeral": True,
                            "network_disabled": True,
                            "healthy": True,
                        },
                        "results": [
                            {
                                "test_id": tid,
                                "outcome": "patch_verified",
                                "passed": True,
                                "revision": patched_rev,
                            }
                            for tid in body["test_ids"]
                        ],
                        "limitations": ["Ephemeral docker sandbox only."],
                    },
                    "events": [],
                },
            )
        return httpx.Response(404, json={"detail": "not found"})

    runner = SecurityServicePatchRunner(
        base_url="http://127.0.0.1:8100",
        token=secret_token,
        source_target=STAND_IN_TARGET.target_id,
        transport=httpx.MockTransport(handler),
    )
    non_fixture_ctx = ctx.model_copy(update={"fixture_mode": False})
    orch = IsolatedPatchVerificationOrchestrator(runner=runner)
    report = await orch.verify_candidate(non_fixture_ctx)

    assert seen_headers == [secret_token, secret_token]
    assert report.decision.accepted is True
    assert report.decision.overall_status == TestExecutionStatus.TEST_PASSED
    assert report.patch_test_result is not None
    assert secret_token not in report.patch_test_result.sanitized_logs


@pytest.mark.asyncio
async def test_security_service_timeout_maps_to_infra_error_outcome_unknown() -> None:
    ctx = _base_context().model_copy(update={"fixture_mode": False})

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    runner = SecurityServicePatchRunner(
        base_url="http://127.0.0.1:8100",
        token="valid-token-value",
        transport=httpx.MockTransport(timeout_handler),
    )
    orch = IsolatedPatchVerificationOrchestrator(runner=runner)
    report = await orch.verify_candidate(ctx)

    assert report.decision.accepted is False
    assert report.decision.overall_status == TestExecutionStatus.INFRASTRUCTURE_ERROR
    assert report.patch_test_result is not None
    assert "RUNNER_TIMEOUT_OUTCOME_UNKNOWN" in report.patch_test_result.sanitized_logs


@pytest.mark.asyncio
async def test_demos_and_evaluator_zero_unsafe_false_passes() -> None:
    demos = await run_all_verification_demos()
    assert demos["demo_a_verified_pass"].decision.accepted is True
    assert demos["demo_h_unsupported_target"].decision.overall_status == TestExecutionStatus.NOT_RUN

    summary = await evaluate_patch_verification_cases()
    assert summary["unsafe_false_pass_count"] == 0
    assert summary["all_passed"] is True
