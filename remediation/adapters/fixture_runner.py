"""Explicit offline fixture PatchTestRunner for deterministic Phase 08 simulation."""

from __future__ import annotations

import uuid
from typing import Literal

from shared.enums import (
    ArtifactType,
    EvidenceProvenance,
    RedactionStatus,
    TestExecutionStatus,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    IndividualTestOutcome,
    PatchProposal,
    PatchTestResult,
)
from shared.serialization import sha256_bytes

from remediation.patching.source_access import STAND_IN_TARGET
from remediation.verification.models import compute_expected_patched_revision

FixtureScenario = Literal[
    "pass",
    "security_fail",
    "functional_fail",
    "smoke_fail",
    "missing_tests",
    "base_revision_mismatch",
    "patched_revision_mismatch",
    "runtime_revision_mismatch",
    "runtime_revision_missing",
    "hash_mismatch",
    "infra_error",
    "timeout_outcome_unknown",
    "artifact_corrupted",
    "insufficient_isolation",
    "not_run",
]


def _categorize(test_id: str) -> str:
    lower = test_id.lower()
    if "smoke" in lower:
        return "smoke"
    if "negative" in lower or "invalid" in lower or "empty" in lower:
        return "negative_input"
    if "func" in lower or "normal" in lower or ("search" in lower and "sqli" not in lower):
        return "functional"
    return "security"


class FixturePatchTestRunner:
    """Explicit offline PatchTestRunner simulating isolated verification outcomes."""

    def __init__(
        self,
        *,
        scenario: FixtureScenario = "pass",
        source_target: str = STAND_IN_TARGET.target_id,
    ) -> None:
        self._scenario: FixtureScenario = scenario
        self._source_target = source_target
        self._results: dict[str, PatchTestResult] = {}
        self._artifacts: dict[str, list[ArtifactReference]] = {}

    async def submit_patch_test(self, proposal: PatchProposal) -> str:
        result, artifacts = await self.execute_verified_run(
            proposal,
            source_target=self._source_target,
            base_revision=proposal.source_revision,
            test_ids=list(proposal.required_tests),
            expected_patched_revision=compute_expected_patched_revision(
                proposal.source_revision, proposal.candidate_content_hash
            ),
        )
        self._results[result.test_run_id] = result
        self._artifacts[result.test_run_id] = artifacts
        return result.test_run_id

    async def get_test_run_status(self, test_run_id: str) -> str:
        return self._results[test_run_id].overall_status.value

    async def get_patch_test_result(self, test_run_id: str) -> PatchTestResult:
        return self._results[test_run_id]

    def get_run_artifacts(self, test_run_id: str) -> list[ArtifactReference]:
        return list(self._artifacts.get(test_run_id, []))

    async def execute_verified_run(
        self,
        proposal: PatchProposal,
        *,
        source_target: str,
        base_revision: str,
        test_ids: list[str],
        expected_patched_revision: str | None = None,
    ) -> tuple[PatchTestResult, list[ArtifactReference]]:
        started = utc_now()
        completed = utc_now()
        test_run_id = f"trun_{uuid.uuid4().hex[:32]}"
        art_id = f"art_{uuid.uuid4().hex[:32]}"
        expected_patched = expected_patched_revision or compute_expected_patched_revision(
            base_revision, proposal.candidate_content_hash
        )

        scenario = self._scenario
        tested_base = base_revision
        tested_hash = proposal.candidate_content_hash
        runner_patched: str | None = expected_patched
        runtime_rev: str | None = expected_patched
        isolation_metadata: dict[str, object] = {
            "mode": "fixture",
            "ephemeral": True,
            "network_disabled": True,
            "read_only_root": True,
            "healthy": True,
            "require_runtime_revision_match": True,
        }

        outcomes: list[IndividualTestOutcome] = []
        overall = TestExecutionStatus.TEST_PASSED
        limitations = ["Simulated offline fixture verification run."]

        if scenario == "missing_tests" and len(test_ids) > 1:
            effective_ids = test_ids[:-1]
        else:
            effective_ids = list(test_ids)

        if scenario in ("infra_error", "timeout_outcome_unknown"):
            overall = TestExecutionStatus.INFRASTRUCTURE_ERROR
            runtime_rev = None
            runner_patched = None
            isolation_metadata["healthy"] = False
            if scenario == "timeout_outcome_unknown":
                limitations.append("RUNNER_TIMEOUT_OUTCOME_UNKNOWN: sandbox timed out.")
            else:
                limitations.append("Simulated sandbox container launch failure.")
        elif scenario == "not_run":
            overall = TestExecutionStatus.NOT_RUN
            runtime_rev = None
            runner_patched = None
            limitations.append("Verification did not run.")
        else:
            for tid in effective_ids:
                cat = _categorize(tid)
                st = TestExecutionStatus.TEST_PASSED
                msg = f"Fixture {tid} passed."
                if scenario == "security_fail" and cat == "security":
                    st = TestExecutionStatus.TEST_FAILED
                    msg = f"Security regression {tid} failed: exploit still succeeded."
                elif scenario == "functional_fail" and cat in ("functional", "negative_input"):
                    st = TestExecutionStatus.TEST_FAILED
                    msg = f"Functional regression {tid} failed."
                elif scenario == "smoke_fail" and cat == "smoke":
                    st = TestExecutionStatus.TEST_FAILED
                    msg = f"Unrelated smoke test {tid} failed."
                outcomes.append(
                    IndividualTestOutcome(
                        test_name=tid,
                        category=cat,
                        status=st,
                        duration_seconds=0.05,
                        message=msg,
                    )
                )
            if any(o.status == TestExecutionStatus.TEST_FAILED for o in outcomes):
                overall = TestExecutionStatus.TEST_FAILED

        if scenario == "base_revision_mismatch":
            tested_base = f"{base_revision}_stale"
        elif scenario == "patched_revision_mismatch":
            runner_patched = f"{expected_patched}_wrong"
        elif scenario == "runtime_revision_mismatch":
            runtime_rev = f"{expected_patched}_unpatched_runtime"
        elif scenario == "runtime_revision_missing":
            runtime_rev = None
        elif scenario == "hash_mismatch":
            tested_hash = sha256_bytes(b"different-candidate-diff")
        elif scenario == "insufficient_isolation":
            isolation_metadata = {
                "mode": "host",
                "ephemeral": False,
                "network_disabled": False,
                "healthy": True,
                "require_runtime_revision_match": True,
            }

        log_text = (
            f"fixture scenario={scenario} patch_id={proposal.patch_id} "
            f"status={overall.value} outcomes={len(outcomes)}"
        )
        artifacts: list[ArtifactReference] = []
        if scenario != "artifact_corrupted":
            artifacts.append(
                ArtifactReference(
                    artifact_id=art_id,
                    incident_id=proposal.incident_id,
                    artifact_type=ArtifactType.PATCH_TEST_LOG,
                    content_hash=sha256_bytes(log_text.encode("utf-8")),
                    storage_ref=f"fixtures/{proposal.incident_id}/{art_id}.log",
                    created_at=completed,
                    producer="fixture_patch_test_runner",
                    provenance=EvidenceProvenance.REFERENCE_FIXTURE,
                    content_type="text/plain",
                    size_bytes=len(log_text.encode("utf-8")),
                    source_revision=runner_patched or tested_base,
                    redaction_status=RedactionStatus.REDACTED,
                )
            )
        else:
            # Mismatched incident_id simulates corrupted/untrusted evidence artifact
            artifacts.append(
                ArtifactReference(
                    artifact_id=art_id,
                    incident_id="inc_00000000000000000000000000009999",
                    artifact_type=ArtifactType.PATCH_TEST_LOG,
                    content_hash=sha256_bytes(b"corrupted"),
                    storage_ref=f"fixtures/{proposal.incident_id}/{art_id}.log",
                    created_at=completed,
                    producer="fixture_patch_test_runner",
                    provenance=EvidenceProvenance.LLM_INTERPRETATION,
                    content_type="text/plain",
                    size_bytes=9,
                    source_revision=tested_base,
                    redaction_status=RedactionStatus.REDACTED,
                )
            )

        result = PatchTestResult(
            test_run_id=test_run_id,
            patch_id=proposal.patch_id,
            incident_id=proposal.incident_id,
            expected_source_revision=base_revision,
            tested_source_revision=tested_base,
            tested_candidate_hash=tested_hash,
            individual_outcomes=outcomes,
            overall_status=overall,
            artifact_ids=[art_id],
            sanitized_logs=log_text,
            started_at=started,
            completed_at=completed,
            exit_code=0 if overall == TestExecutionStatus.TEST_PASSED else 1,
            limitations=limitations,
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
            base_source_revision=tested_base,
            expected_patched_revision=expected_patched,
            runner_computed_patched_revision=runner_patched,
            runtime_observed_revision=runtime_rev,
            source_target=source_target,
            required_test_ids=list(test_ids),
            isolation_metadata=isolation_metadata,
            verification_policy_version="isolated_verification_v1",
        )
        return result, artifacts
