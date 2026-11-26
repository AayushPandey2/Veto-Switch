"""HTTP adapter integrating the isolated Phase 08 orchestrator with security.service."""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx
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

_MAX_RESPONSE_BYTES = 512 * 1024


def _new_test_run_id() -> str:
    return f"trun_{uuid.uuid4().hex[:32]}"


def _new_artifact_id() -> str:
    return f"art_{uuid.uuid4().hex[:32]}"


def _map_status(raw_status: str) -> TestExecutionStatus:
    normalized = raw_status.strip().lower()
    if normalized in ("passed", "patch_verified", "test_passed"):
        return TestExecutionStatus.TEST_PASSED
    if normalized in ("failed", "patch_failed", "test_failed"):
        return TestExecutionStatus.TEST_FAILED
    if normalized in ("not_run", "skipped"):
        return TestExecutionStatus.NOT_RUN
    return TestExecutionStatus.INFRASTRUCTURE_ERROR


def _infer_category(test_id: str) -> str:
    lower = test_id.lower()
    if "smoke" in lower:
        return "smoke"
    if "negative" in lower or "invalid" in lower or "empty" in lower:
        return "negative_input"
    if "func" in lower or "normal" in lower or ("search" in lower and "sqli" not in lower):
        return "functional"
    return "security"


class SecurityServicePatchRunner:
    """Async PatchTestRunner adapter communicating with the isolated security HTTP service."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:8100",
        token: str | None = None,
        source_target: str = STAND_IN_TARGET.target_id,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = (
            token if token is not None else os.environ.get("KSX_SECURITY_SERVICE_TOKEN", "")
        )
        self._source_target = source_target
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._transport = transport
        self._results: dict[str, PatchTestResult] = {}
        self._artifacts: dict[str, list[ArtifactReference]] = {}
        self._statuses: dict[str, str] = {}

    def _auth_headers(self) -> dict[str, str]:
        if not self._token or self._token == "change-me":
            raise ValueError("KSX_SECURITY_SERVICE_TOKEN is missing or unset.")
        return {"X-KSX-Token": self._token}

    def _build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            follow_redirects=False,
            timeout=self._timeout_seconds,
            transport=self._transport,
        )

    def _decode_bounded_json(self, response: httpx.Response) -> dict[str, Any]:
        raw = response.content
        if len(raw) > self._max_response_bytes:
            raise ValueError(
                "Security runner response exceeded max_response_bytes "
                f"({self._max_response_bytes})."
            )
        parsed = response.json()
        if not isinstance(parsed, dict):
            raise ValueError("Security runner returned non-object JSON payload.")
        return parsed

    async def fetch_health(self) -> dict[str, Any]:
        async with self._build_client() as client:
            resp = await client.get("/health")
            resp.raise_for_status()
            return self._decode_bounded_json(resp)

    async def fetch_registry(self) -> dict[str, Any]:
        async with self._build_client() as client:
            resp = await client.get("/registry")
            resp.raise_for_status()
            return self._decode_bounded_json(resp)

    async def fetch_targets(self) -> dict[str, Any]:
        async with self._build_client() as client:
            resp = await client.get("/targets")
            resp.raise_for_status()
            return self._decode_bounded_json(resp)

    async def fetch_base_revision(self, source: str | None = None) -> dict[str, Any]:
        target_source = source or self._source_target
        async with self._build_client() as client:
            resp = await client.get("/patches/base-revision", params={"source": target_source})
            resp.raise_for_status()
            return self._decode_bounded_json(resp)

    async def fetch_incident_artifacts(self, incident_id: str) -> dict[str, Any]:
        async with self._build_client() as client:
            resp = await client.get(f"/artifacts/{incident_id}")
            resp.raise_for_status()
            return self._decode_bounded_json(resp)

    async def submit_patch_test(self, proposal: PatchProposal) -> str:
        """Submit candidate patch + test run to the security runner and return test_run_id."""
        result, artifacts = await self.execute_verified_run(
            proposal,
            source_target=self._source_target,
            base_revision=proposal.source_revision,
            test_ids=list(proposal.required_tests),
        )
        self._results[result.test_run_id] = result
        self._artifacts[result.test_run_id] = artifacts
        self._statuses[result.test_run_id] = result.overall_status.value
        return result.test_run_id

    async def get_test_run_status(self, test_run_id: str) -> str:
        if test_run_id not in self._statuses:
            raise KeyError(f"Unknown test_run_id: {test_run_id}")
        return self._statuses[test_run_id]

    async def get_patch_test_result(self, test_run_id: str) -> PatchTestResult:
        if test_run_id not in self._results:
            raise KeyError(f"Unknown test_run_id: {test_run_id}")
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
        """Execute synchronous POST /patches and POST /patch-tests safely."""
        started = utc_now()
        test_run_id = _new_test_run_id()

        try:
            headers = self._auth_headers()
        except ValueError as exc:
            return self._infra_error_result(
                test_run_id=test_run_id,
                proposal=proposal,
                base_revision=base_revision,
                expected_patched_revision=expected_patched_revision,
                source_target=source_target,
                required_test_ids=test_ids,
                started_at=started,
                reason=str(exc),
                limitation="Security service token not configured.",
            )

        try:
            async with self._build_client() as client:
                submit_resp = await client.post(
                    "/patches",
                    headers=headers,
                    json={
                        "patch_id": proposal.patch_id,
                        "incident_id": proposal.incident_id,
                        "diff": proposal.unified_diff,
                        "base_revision": base_revision,
                        "source": source_target,
                    },
                )
                if submit_resp.status_code >= 400:
                    detail = submit_resp.text[:300]
                    return self._infra_error_result(
                        test_run_id=test_run_id,
                        proposal=proposal,
                        base_revision=base_revision,
                        expected_patched_revision=expected_patched_revision,
                        source_target=source_target,
                        required_test_ids=test_ids,
                        started_at=started,
                        reason=f"POST /patches rejected ({submit_resp.status_code}): {detail}",
                        limitation="Candidate patch rejected by isolated security service.",
                    )
                self._decode_bounded_json(submit_resp)

                run_resp = await client.post(
                    "/patch-tests",
                    headers=headers,
                    json={
                        "patch_id": proposal.patch_id,
                        "revision": base_revision,
                        "test_ids": test_ids,
                    },
                )
                if run_resp.status_code >= 400:
                    detail = run_resp.text[:300]
                    return self._infra_error_result(
                        test_run_id=test_run_id,
                        proposal=proposal,
                        base_revision=base_revision,
                        expected_patched_revision=expected_patched_revision,
                        source_target=source_target,
                        required_test_ids=test_ids,
                        started_at=started,
                        reason=f"POST /patch-tests failed ({run_resp.status_code}): {detail}",
                        limitation="Patch test execution failed at security service.",
                    )
                payload = self._decode_bounded_json(run_resp)
        except httpx.TimeoutException:
            return self._infra_error_result(
                test_run_id=test_run_id,
                proposal=proposal,
                base_revision=base_revision,
                expected_patched_revision=expected_patched_revision,
                source_target=source_target,
                required_test_ids=test_ids,
                started_at=started,
                reason="RUNNER_TIMEOUT_OUTCOME_UNKNOWN",
                limitation="Security service timed out; outcome unknown and never treated as pass.",
            )
        except (httpx.HTTPError, ValueError) as exc:
            return self._infra_error_result(
                test_run_id=test_run_id,
                proposal=proposal,
                base_revision=base_revision,
                expected_patched_revision=expected_patched_revision,
                source_target=source_target,
                required_test_ids=test_ids,
                started_at=started,
                reason=f"Security service communication error: {type(exc).__name__}",
                limitation="Security service unavailable or returned invalid payload.",
            )

        return self._normalize_report(
            test_run_id=test_run_id,
            proposal=proposal,
            base_revision=base_revision,
            expected_patched_revision=expected_patched_revision,
            source_target=source_target,
            required_test_ids=test_ids,
            started_at=started,
            payload=payload,
        )

    def _normalize_report(
        self,
        *,
        test_run_id: str,
        proposal: PatchProposal,
        base_revision: str,
        expected_patched_revision: str | None,
        source_target: str,
        required_test_ids: list[str],
        started_at: Any,
        payload: dict[str, Any],
    ) -> tuple[PatchTestResult, list[ArtifactReference]]:
        completed = utc_now()
        raw_report = payload.get("report")
        report: dict[str, Any] = raw_report if isinstance(raw_report, dict) else payload
        raw_results = report.get("results") or []
        outcomes: list[IndividualTestOutcome] = []
        observed_revisions: list[str] = []

        for item in raw_results:
            if not isinstance(item, dict):
                continue
            tid = str(item.get("test_id") or "")
            if not tid:
                continue
            status = _map_status(str(item.get("outcome") or "infrastructure_error"))
            rev = item.get("revision")
            if isinstance(rev, str) and rev:
                observed_revisions.append(rev)
            outcomes.append(
                IndividualTestOutcome(
                    test_name=tid,
                    category=_infer_category(tid),
                    status=status,
                    duration_seconds=0.1,
                    message=str(item.get("detail") or item.get("outcome") or ""),
                )
            )

        overall = _map_status(str(report.get("status") or "infrastructure_error"))
        runner_patched_rev = report.get("patched_revision")
        runtime_rev: str | None = None
        if observed_revisions:
            unique_revs = set(observed_revisions)
            runtime_rev = observed_revisions[0] if len(unique_revs) == 1 else "__mixed__"

        raw_sandbox = report.get("sandbox")
        sandbox_logs: dict[str, Any] = raw_sandbox if isinstance(raw_sandbox, dict) else {}
        mode = str(sandbox_logs.get("mode") or "docker")
        isolation_metadata = {
            "mode": mode,
            "ephemeral": bool(
                sandbox_logs.get("ephemeral", mode in ("docker", "ephemeral_sandbox"))
            ),
            "network_disabled": bool(
                sandbox_logs.get("network_disabled", mode in ("docker", "ephemeral_sandbox"))
            ),
            "read_only_root": bool(sandbox_logs.get("read_only_root", False)),
            "healthy": bool(sandbox_logs.get("healthy", False)),
            "require_runtime_revision_match": True,
        }

        art_id = str(report.get("evidence_id") or _new_artifact_id())
        if not art_id.startswith("art_"):
            art_id = _new_artifact_id()

        canonical_bytes = json.dumps(report, sort_keys=True, default=str).encode("utf-8")
        artifact = ArtifactReference(
            artifact_id=art_id,
            incident_id=proposal.incident_id,
            artifact_type=ArtifactType.PATCH_TEST_LOG,
            content_hash=sha256_bytes(canonical_bytes),
            storage_ref=str(
                report.get("artifact_path")
                or f"artifacts/{proposal.incident_id}/{art_id}.json"
            ),
            created_at=completed,
            producer="security_service_patch_runner",
            provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
            content_type="application/json",
            size_bytes=len(canonical_bytes),
            source_revision=str(runner_patched_rev or base_revision),
            redaction_status=RedactionStatus.REDACTED,
        )

        limitations = [str(lim) for lim in (report.get("limitations") or [])]
        if report.get("reason"):
            limitations.append(f"runner_reason: {report['reason']}")

        tested_hash = str(report.get("diff_sha256") or proposal.candidate_content_hash)
        tested_base = str(report.get("base_revision") or base_revision)

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
            sanitized_logs=(
                f"security_service status={overall.value}; "
                f"tests={len(outcomes)}; patched_revision={runner_patched_rev}"
            ),
            started_at=started_at,
            completed_at=completed,
            exit_code=0 if overall == TestExecutionStatus.TEST_PASSED else 1,
            limitations=limitations,
            provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
            base_source_revision=tested_base,
            expected_patched_revision=expected_patched_revision,
            runner_computed_patched_revision=(
                str(runner_patched_rev) if runner_patched_rev else None
            ),
            runtime_observed_revision=runtime_rev,
            source_target=source_target,
            required_test_ids=list(required_test_ids),
            isolation_metadata=isolation_metadata,
            verification_policy_version="isolated_verification_v1",
        )
        return result, [artifact]

    def _infra_error_result(
        self,
        *,
        test_run_id: str,
        proposal: PatchProposal,
        base_revision: str,
        expected_patched_revision: str | None,
        source_target: str,
        required_test_ids: list[str],
        started_at: Any,
        reason: str,
        limitation: str,
    ) -> tuple[PatchTestResult, list[ArtifactReference]]:
        completed = utc_now()
        art_id = _new_artifact_id()
        log_text = f"isolated verification infrastructure error: {reason}"
        artifact = ArtifactReference(
            artifact_id=art_id,
            incident_id=proposal.incident_id,
            artifact_type=ArtifactType.PATCH_TEST_LOG,
            content_hash=sha256_bytes(log_text.encode("utf-8")),
            storage_ref=f"artifacts/{proposal.incident_id}/{art_id}.log",
            created_at=completed,
            producer="security_service_patch_runner",
            provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
            content_type="text/plain",
            size_bytes=len(log_text.encode("utf-8")),
            source_revision=base_revision,
            redaction_status=RedactionStatus.REDACTED,
        )
        result = PatchTestResult(
            test_run_id=test_run_id,
            patch_id=proposal.patch_id,
            incident_id=proposal.incident_id,
            expected_source_revision=base_revision,
            tested_source_revision=base_revision,
            tested_candidate_hash=proposal.candidate_content_hash,
            individual_outcomes=[],
            overall_status=TestExecutionStatus.INFRASTRUCTURE_ERROR,
            artifact_ids=[art_id],
            sanitized_logs=log_text,
            started_at=started_at,
            completed_at=completed,
            exit_code=None,
            limitations=[limitation, reason],
            provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
            base_source_revision=base_revision,
            expected_patched_revision=expected_patched_revision,
            runner_computed_patched_revision=None,
            runtime_observed_revision=None,
            source_target=source_target,
            required_test_ids=list(required_test_ids),
            isolation_metadata={
                "mode": "docker",
                "ephemeral": False,
                "network_disabled": True,
                "healthy": False,
            },
            verification_policy_version="isolated_verification_v1",
        )
        return result, [artifact]
