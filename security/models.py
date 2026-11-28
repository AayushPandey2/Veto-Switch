"""Security-lane wire DTOs.

Decoupled from ``shared.schemas`` canonical domain models so security-lane
wire semantics (e.g. ``phase="before"``, ``category="sqli"``,
``observed_flag_state``) remain stable and are normalized into canonical
``shared.schemas`` models via ``agent_core/adapters/security_contract.py``.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Phase = Literal["before", "after_containment", "after_patch"]

# What actually happened. `passed` on VerificationResult only answers "did the
# phase-specific assertion hold"; `outcome` says why, without ambiguity.
Outcome = Literal[
    "exploit_reproduced",      # before: vulnerability confirmed on the baseline
    "exploit_not_reproduced",  # before: could not reproduce (finding stays suspected)
    "contained",               # after_containment: blocked, flag observed, smoke ok
    "contained_smoke_failed",  # after_containment: blocked, but an unrelated route broke
    "containment_failed",      # after_containment: exploit still works on some route
    "flag_mismatch",           # app did not observe the expected flag state (e.g. cache lag)
    "patch_verified",          # after_patch: exploit blocked AND functional tests pass
    "patch_failed",            # after_patch: exploit still works or functionality broke
    "revision_mismatch",       # code under test is not the code requested: untrusted
    "infrastructure_error",    # target unreachable, timeout, launch failure
    "not_run",                 # refused before running (unknown test/target, bad request)
]

PHASE_SEMANTICS = {
    "before": "passed=true means the vulnerability REPRODUCED on the baseline (expected for a real finding).",
    "after_containment": "passed=true means the exploit was BLOCKED on every probed route and the app "
                         "observed the expected flag state.",
    "after_patch": "passed=true means the exploit was BLOCKED and functional + negative-input tests passed "
                   "on the patched revision.",
}


class CheckResult(BaseModel):
    name: str
    passed: bool | None = None          # None = not run
    detail: str = ""
    route: str | None = None
    status_code: int | None = None
    variant: str | None = None


class SecurityVerificationResult(BaseModel):
    verification_id: str | None = None
    incident_id: str
    test_id: str
    target_id: str
    phase: Phase
    outcome: Outcome
    passed: bool | None = None
    observed_flag_state: str | None = None
    artifact_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence_id: str | None = None
    revision: str | None = None             # revision the app reported
    requested_revision: str | None = None   # revision the caller asked us to test
    expected_flags: dict[str, Any] = Field(default_factory=dict)
    observed_flags: dict[str, Any] = Field(default_factory=dict)
    checks: list[CheckResult] = Field(default_factory=list)
    smoke: list[CheckResult] = Field(default_factory=list)
    started_at_utc: str | None = None
    finished_at_utc: str | None = None
    phase_semantics: str = ""


class SecurityFinding(BaseModel):
    """A normalized security-lane finding DTO with the extra evidence the security brief requires."""

    finding_id: str
    incident_id: str
    category: str
    affected_route: str | None = None
    affected_component: str = "unknown_component"
    severity: str = "medium"
    status: str = "suspected"
    evidence_ids: list[str] = Field(default_factory=list)
    repository_revision: str | None = None
    environment: str | None = None
    test_id: str | None = None
    target_id: str | None = None
    observed_behavior: str = ""
    severity_rationale: str = ""
    tool: str = ""
    tool_version: str = ""
    raw_artifact: str | None = None
    fingerprint: str = ""
    advisory: dict[str, Any] | None = None


class TestRunRequest(BaseModel):
    __test__ = False  # not a pytest class
    test_id: str
    target_id: str
    phase: Phase
    incident_id: str
    revision: str | None = None


class ArtifactRef(BaseModel):
    evidence_id: str
    path: str
    sha256: str
    kind: str


class SecurityIncidentEvent(BaseModel):
    """Security-lane wire event DTO normalized by the orchestration adapter."""

    incident_id: str
    event_type: str
    actor: str
    timestamp_utc: str
    payload: dict[str, Any]
