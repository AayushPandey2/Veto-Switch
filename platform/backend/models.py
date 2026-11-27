"""Request models for the standalone local operator API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Scenario = Literal["search_sqli", "path_traversal"]
FindingCategory = Literal["sqli", "path_traversal", "dependency_cve", "other"]
FindingSeverity = Literal["low", "medium", "high", "critical", "unknown"]


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: Scenario
    reporter: str = Field(min_length=1, max_length=80)
    evidence_summary: str = Field(min_length=1, max_length=500)


class NormalizedFindingCreate(BaseModel):
    """Stable intake contract for security tools and teammate agent services."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    category: FindingCategory
    affected_route: str | None = Field(default=None, max_length=256)
    affected_component: str | None = Field(default=None, max_length=256)
    severity: FindingSeverity = "unknown"
    status: Literal["suspected", "reproduced"]
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    evidence_summary: str = Field(min_length=1, max_length=500)
    reporter: str = Field(default="security-integration", min_length=1, max_length=80)


class ReleaseDecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    actor: str = Field(min_length=1, max_length=80)
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=500)


class ReleaseApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class DecisionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    actor: str = Field(min_length=1, max_length=80)
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=500)


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class RolloutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    percentage: Literal[5, 25, 50, 100]


class SyntheticTrafficRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests: int = Field(ge=1, le=500)
    route: Literal["/search", "/files"] = "/search"
