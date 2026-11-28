"""Shared Pytest configuration and reusable offline fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from shared.enums import ApprovalStatus, ProposalType
from shared.identifiers import (
    generate_approval_id,
    generate_artifact_id,
    generate_finding_id,
    generate_idempotency_token,
    generate_incident_id,
    generate_proposal_id,
)
from shared.schemas import ApprovalDecision, ContainmentProposal


@pytest.fixture(autouse=True)
def _isolated_offline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests run strictly offline without relying on external credentials."""
    for var in (
        "KILLSWITCH_LLM_API_KEY",
        "KILLSWITCH_PLATFORM_FLAGSMITH_ENVIRONMENT_KEY",
        "KILLSWITCH_PLATFORM_FLAGSMITH_MANAGEMENT_TOKEN",
        "KILLSWITCH_PLATFORM_APPROVAL_SIGNING_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def sample_containment_proposal() -> ContainmentProposal:
    """Return a valid ContainmentProposal with a freshly computed canonical hash."""
    now = datetime(2026, 11, 26, 1, 0, 0, tzinfo=UTC)
    return ContainmentProposal.with_computed_hash(
        proposal_id=generate_proposal_id(),
        incident_id=generate_incident_id(),
        proposal_type=ProposalType.CONTAINMENT_FLAG_DISABLE,
        environment="demo-staging",
        flag_name="search_v1",
        desired_enabled=False,
        expected_current_enabled=True,
        reason="Disable vulnerable search_v1 endpoint during SQLi incident.",
        alternatives=["Switch to search_v2 (unverified deployment)"],
        expected_disruption="/search routes to /health fallback.",
        evidence_ids=[generate_artifact_id()],
        approval_required=True,
        registry_version="1.0.0-demo",
        created_at=now,
        expires_at=now + timedelta(minutes=15),
        idempotency_token=generate_idempotency_token(),
        rollback_considerations=["Verify parameterized query before re-enabling."],
    )


@pytest.fixture()
def sample_approval_factory():
    """Factory creating an ApprovalDecision matched to a ContainmentProposal."""

    def _build(
        proposal: ContainmentProposal,
        *,
        decision: ApprovalStatus = ApprovalStatus.APPROVED,
        decided_at: datetime | None = None,
        expires_at: datetime | None = None,
        proposal_hash: str | None = None,
        rejection_reason: str | None = None,
    ) -> ApprovalDecision:
        decided = decided_at or (proposal.created_at + timedelta(minutes=1))
        expires = expires_at or proposal.expires_at
        return ApprovalDecision(
            approval_id=generate_approval_id(),
            proposal_id=proposal.proposal_id,
            proposal_hash=proposal_hash or proposal.proposal_hash,
            incident_id=proposal.incident_id,
            actor_id="secops_test_operator",
            decision=decision,
            decided_at=decided,
            expires_at=expires,
            rejection_reason=rejection_reason,
            authorization_context_ref="authctx_test_session_001",
            nonce=f"nonce_{generate_finding_id()}",
        )

    return _build
