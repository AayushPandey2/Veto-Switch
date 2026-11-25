"""Shared Killswitch X contracts (frozen Day 1, per the master roadmap section 4).

Every lane imports these models. Breaking changes need a version bump and a
cross-lane PR review; lanes extend them by subclassing, never by editing fields here.
"""

from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"


class Finding(BaseModel):
    finding_id: str
    incident_id: str
    category: Literal['sqli', 'path_traversal', 'dependency_cve', 'other']
    affected_route: str | None = None
    affected_component: str | None = None
    severity: Literal['low', 'medium', 'high', 'critical', 'unknown'] = 'unknown'
    status: Literal['suspected', 'reproduced']
    evidence_ids: list[str] = Field(default_factory=list)


class ContainmentProposal(BaseModel):
    proposal_id: str
    incident_id: str
    environment: str
    flag_name: str
    desired_enabled: bool
    reason: str
    alternatives: list[str] = Field(default_factory=list)
    expected_disruption: str
    evidence_ids: list[str]
    requires_approval: bool = True


class VerificationResult(BaseModel):
    incident_id: str
    test_id: str
    phase: Literal['before', 'after_containment', 'after_patch']
    passed: bool
    observed_flag_state: str | None = None
    artifact_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class IncidentEvent(BaseModel):
    incident_id: str
    event_type: str
    actor: str
    timestamp_utc: str
    payload: dict
