"""Request models for the standalone local operator API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Scenario = Literal["search_sqli", "path_traversal"]


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: Scenario
    reporter: str = Field(min_length=1, max_length=80)
    evidence_summary: str = Field(min_length=1, max_length=500)


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
