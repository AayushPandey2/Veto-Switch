"""Compatibility adapter normalizing ``feat/security`` payloads into canonical contracts.

This adapter bridges known representation differences between the cybersecurity
branch (``security/models.py``, ``security/registry.py``) and ``shared/schemas.py``
without duplicating canonical domain models or inventing missing metadata.
"""

from __future__ import annotations

from typing import Any

from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    MappingReasonCode,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.schemas import Finding, VerificationResult
from shared.serialization import canonical_json, sha256_text

_CATEGORY_MAP: dict[str, VulnerabilityCategory] = {
    "sqli": VulnerabilityCategory.SQL_INJECTION,
    "sql_injection": VulnerabilityCategory.SQL_INJECTION,
    "path_traversal": VulnerabilityCategory.PATH_TRAVERSAL,
    "traversal": VulnerabilityCategory.PATH_TRAVERSAL,
    "dependency_cve": VulnerabilityCategory.DEPENDENCY_CVE,
    "cve": VulnerabilityCategory.DEPENDENCY_CVE,
    "other": VulnerabilityCategory.OTHER,
}

_PHASE_MAP: dict[str, VerificationPhase] = {
    "before": VerificationPhase.BEFORE_CONTAINMENT,
    "before_containment": VerificationPhase.BEFORE_CONTAINMENT,
    "after_containment": VerificationPhase.AFTER_CONTAINMENT,
    "after_patch": VerificationPhase.AFTER_PATCH,
}

_SEVERITY_MAP: dict[str, VulnerabilitySeverity] = {
    "low": VulnerabilitySeverity.LOW,
    "medium": VulnerabilitySeverity.MEDIUM,
    "high": VulnerabilitySeverity.HIGH,
    "critical": VulnerabilitySeverity.CRITICAL,
    "unknown": VulnerabilitySeverity.UNKNOWN,
}

# Security outcomes mapped to (TestExecutionStatus, canonical passed: bool | None)
_OUTCOME_MAP: dict[str, tuple[TestExecutionStatus, bool | None]] = {
    "exploit_reproduced": (TestExecutionStatus.TEST_PASSED, True),
    "contained": (TestExecutionStatus.TEST_PASSED, True),
    "patch_verified": (TestExecutionStatus.TEST_PASSED, True),
    "exploit_not_reproduced": (TestExecutionStatus.TEST_FAILED, False),
    "contained_smoke_failed": (TestExecutionStatus.TEST_FAILED, False),
    "containment_failed": (TestExecutionStatus.TEST_FAILED, False),
    "flag_mismatch": (TestExecutionStatus.TEST_FAILED, False),
    "patch_failed": (TestExecutionStatus.TEST_FAILED, False),
    "revision_mismatch": (TestExecutionStatus.TEST_FAILED, False),
    "infrastructure_error": (TestExecutionStatus.INFRASTRUCTURE_ERROR, None),
    "not_run": (TestExecutionStatus.NOT_RUN, None),
}


def normalize_security_category(raw_category: str) -> VulnerabilityCategory:
    """Normalize security-lane category strings (e.g. ``sqli`` -> ``sql_injection``)."""
    return _CATEGORY_MAP.get(raw_category.strip().lower(), VulnerabilityCategory.OTHER)


def normalize_security_phase(raw_phase: str) -> VerificationPhase:
    """Normalize security-lane phase strings (e.g. ``before`` -> ``before_containment``)."""
    key = raw_phase.strip().lower()
    if key not in _PHASE_MAP:
        raise ContractValidationError(
            f"Unsupported security verification phase {raw_phase!r}.",
            context={"raw_phase": raw_phase},
        )
    return _PHASE_MAP[key]


def normalize_security_finding(
    payload: dict[str, Any],
    *,
    incident_id: str | None = None,
    environment: str | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.SECURITY_TEST_OUTPUT,
) -> tuple[Finding, dict[str, Any]]:
    """Normalize a security-lane ``SecurityFinding`` payload into canonical ``Finding``.

    Returns:
        Tuple of ``(Finding, metadata_extras)`` where ``metadata_extras`` preserves
        ``test_id``, ``target_id``, and ``limitations`` without fabricating missing
        incident IDs or revisions.
    """
    resolved_incident_id = payload.get("incident_id") or incident_id
    if not resolved_incident_id:
        raise ContractValidationError(
            "Security finding payload is missing mandatory incident_id.",
            context={"reason_code": MappingReasonCode.INSUFFICIENT_EVIDENCE.value},
        )

    finding_id = payload.get("finding_id")
    if not finding_id:
        raise ContractValidationError("Security finding payload is missing finding_id.")

    raw_status = str(payload.get("status", "suspected")).strip().lower()
    status = (
        FindingStatus.REPRODUCED
        if raw_status == FindingStatus.REPRODUCED.value
        else FindingStatus.SUSPECTED
    )

    evidence_ids = list(payload.get("evidence_ids") or [])
    if not evidence_ids and payload.get("evidence_id"):
        evidence_ids = [str(payload["evidence_id"])]

    raw_tool = payload.get("source_scanner") or payload.get("tool")
    source_scanner = str(raw_tool).strip() if raw_tool else None

    raw_rev = payload.get("repository_revision") or payload.get("revision")
    revision = str(raw_rev).strip() if raw_rev else None

    raw_sev = str(payload.get("severity", "unknown")).strip().lower()
    severity = _SEVERITY_MAP.get(raw_sev, VulnerabilitySeverity.UNKNOWN)

    finding = Finding(
        finding_id=str(finding_id),
        incident_id=str(resolved_incident_id),
        category=normalize_security_category(str(payload.get("category", "other"))),
        affected_route=payload.get("affected_route"),
        affected_component=str(payload.get("affected_component") or "unknown_component"),
        severity=severity,
        status=status,
        evidence_ids=evidence_ids,
        source_scanner=source_scanner,
        repository_revision=revision,
        environment=payload.get("environment") or environment,
        observed_impact=payload.get("observed_impact") or payload.get("observed_behavior"),
        provenance=provenance,
    )
    extras = {
        "test_id": payload.get("test_id"),
        "target_id": payload.get("target_id"),
        "raw_category": payload.get("category"),
        "source_scanner_known": source_scanner is not None,
    }
    return finding, extras


def normalize_security_verification_result(
    payload: dict[str, Any],
    *,
    incident_id: str | None = None,
) -> VerificationResult:
    """Normalize a security-lane ``SecurityVerificationResult`` payload.

    Preserves infrastructure failures as ``TestExecutionStatus.INFRASTRUCTURE_ERROR``
    with ``passed=None`` and keeps ``contained_smoke_failed`` as ``passed=False``.
    """
    resolved_incident_id = payload.get("incident_id") or incident_id
    if not resolved_incident_id:
        raise ContractValidationError("Security verification payload requires incident_id.")

    outcome = str(payload.get("outcome", "")).strip().lower()
    if outcome in _OUTCOME_MAP:
        exec_status, passed = _OUTCOME_MAP[outcome]
    else:
        raw_status = str(payload.get("execution_status", "not_run")).strip().lower()
        exec_status = TestExecutionStatus(raw_status)
        passed = payload.get("passed")

    artifact_ids = list(payload.get("artifact_ids") or payload.get("evidence_ids") or [])
    if not artifact_ids and payload.get("evidence_id"):
        artifact_ids = [str(payload["evidence_id"])]

    vuln_reproduced: bool | None = payload.get("vulnerability_reproduced")
    if outcome == "exploit_reproduced":
        vuln_reproduced = True
    elif outcome in {
        "exploit_not_reproduced",
        "contained",
        "contained_smoke_failed",
        "patch_verified",
    }:
        vuln_reproduced = False
    elif outcome == "containment_failed":
        vuln_reproduced = True

    limitations = list(payload.get("limitations") or [])
    if outcome == "contained_smoke_failed":
        limitations.append("Functional smoke test failed during containment verification.")
    elif outcome == "infrastructure_error" and not limitations:
        limitations.append("Security verification encountered an infrastructure error.")

    infra_error_msg: str | None = None
    if exec_status == TestExecutionStatus.INFRASTRUCTURE_ERROR:
        infra_error_msg = str(
            payload.get("infrastructure_error")
            or payload.get("detail")
            or "Security verification encountered an infrastructure error."
        )

    raw_ver_id = payload.get("verification_id")
    if raw_ver_id:
        ver_id = str(raw_ver_id)
    else:
        ver_id = "ver_" + sha256_text(
            canonical_json(
                {
                    "incident_id": resolved_incident_id,
                    "test_id": payload.get("test_id"),
                    "target_id": payload.get("target_id"),
                    "phase": payload.get("phase"),
                    "outcome": outcome,
                    "evidence_id": payload.get("evidence_id"),
                    "revision": payload.get("tested_revision") or payload.get("revision"),
                }
            )
        )[:16]

    return VerificationResult(
        verification_id=ver_id,
        incident_id=str(resolved_incident_id),
        test_id=str(payload["test_id"]),
        phase=normalize_security_phase(str(payload["phase"])),
        execution_status=exec_status,
        passed=passed,
        vulnerability_reproduced=vuln_reproduced,
        expected_revision=payload.get("expected_revision") or payload.get("requested_revision"),
        tested_revision=payload.get("tested_revision") or payload.get("revision"),
        artifact_ids=artifact_ids,
        infrastructure_error=infra_error_msg,
        limitations=limitations,
        provenance=EvidenceProvenance(
            payload.get("provenance", EvidenceProvenance.SECURITY_TEST_OUTPUT.value)
        ),
    )
