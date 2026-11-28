"""Unit tests for centralized enumerations and exception hierarchy."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from shared.constants import REDACTED_PLACEHOLDER
from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    IncidentState,
    MappingStatus,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
)
from shared.exceptions import (
    ExpiredApprovalError,
    InvalidApprovalError,
    KillswitchError,
    LLMTimeoutError,
)
from shared.schemas import Finding


@pytest.mark.unit
def test_enum_serialized_values_preserve_roadmap_contracts() -> None:
    assert FindingStatus.SUSPECTED.value == "suspected"
    assert FindingStatus.REPRODUCED.value == "reproduced"
    assert MappingStatus.MATCHED.value == "matched"
    assert MappingStatus.AMBIGUOUS.value == "ambiguous"
    assert MappingStatus.UNMAPPED.value == "unmapped"
    assert VerificationPhase.BEFORE_CONTAINMENT.value == "before_containment"
    assert VerificationPhase.AFTER_CONTAINMENT.value == "after_containment"
    assert VerificationPhase.AFTER_PATCH.value == "after_patch"
    assert TestExecutionStatus.TEST_PASSED.value == "test_passed"
    assert TestExecutionStatus.INFRASTRUCTURE_ERROR.value == "infrastructure_error"
    assert RolloutDecisionType.ROLLBACK_PROPOSED.value == "rollback_proposed"
    assert IncidentState.AWAITING_APPROVAL.value == "AWAITING_APPROVAL"
    assert EvidenceProvenance.SYNTHETIC_TELEMETRY.value == "synthetic_telemetry"


@pytest.mark.unit
def test_invalid_enum_and_vulnerability_category_rejected() -> None:
    """Scenarios 3 & 18: Invalid category or enum values must fail validation."""
    with pytest.raises(ValidationError):
        Finding(
            finding_id="fnd_1234",
            incident_id="inc_1234",
            category="buffer_overflow_made_up",  # type: ignore[arg-type]
            affected_component="search_service",
            severity="high",  # type: ignore[arg-type]
            status="suspected",  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError):
        VulnerabilityCategory("invalid_category")

    with pytest.raises(ValueError):
        IncidentState("NON_EXISTENT_STATE")


@pytest.mark.unit
def test_exception_hierarchy_redacts_sensitive_context() -> None:
    err = InvalidApprovalError(
        "Approval hash mismatch",
        context={
            "proposal_id": "prop_1234",
            "api_key": "sk-synthetic-secret-123456",
            "nested": {"management_token": "fs_secret_token_9999"},
        },
    )
    assert err.error_code == "INVALID_APPROVAL"
    assert err.retryable is False
    assert err.context["proposal_id"] == "prop_1234"
    assert err.context["api_key"] == REDACTED_PLACEHOLDER
    assert err.context["nested"]["management_token"] == REDACTED_PLACEHOLDER
    serialized = err.to_dict()
    assert serialized["error_code"] == "INVALID_APPROVAL"
    assert "sk-synthetic-secret" not in str(serialized)

    timeout_err = LLMTimeoutError("Timed out")
    assert timeout_err.retryable is True
    assert isinstance(timeout_err, KillswitchError)
    assert isinstance(ExpiredApprovalError("Expired"), KillswitchError)
