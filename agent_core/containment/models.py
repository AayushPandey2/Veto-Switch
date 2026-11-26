"""Typed models for deterministic containment candidate evaluation, scoring, and ranking."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt
from shared.enums import ContainmentReasonCode
from shared.schemas import (
    ContainmentOption,
    ContainmentProposal,
    KillswitchModel,
)

from agent_core.graph_intelligence.models import BlastRadiusResult, CounterfactualOutcome


class ScoreBreakdown(KillswitchModel):
    """Reproducible deterministic multi-criteria policy score derivation."""

    policy_version: str = Field(min_length=1)
    raw_inputs: dict[str, float] = Field(default_factory=dict)
    weights: dict[str, float] = Field(default_factory=dict)
    weighted_contributions: dict[str, float] = Field(default_factory=dict)
    loss: float = Field(ge=0.0, le=1.0)
    relative_policy_score: float = Field(ge=0.0, le=1.0)


class EvaluatedStrategy(KillswitchModel):
    """Single containment candidate with feasibility, counterfactual, and score."""

    strategy_id: str = Field(min_length=1)
    strategy_priority: StrictInt = Field(default=50, ge=0)
    option: ContainmentOption
    counterfactual: CounterfactualOutcome
    score_breakdown: ScoreBreakdown
    reason_codes: list[ContainmentReasonCode] = Field(default_factory=list)
    execution_supported: StrictBool = False
    requires_approval: StrictBool = True
    authorized_for_execution: StrictBool = False
    action_eligibility: Literal[
        "eligible_for_proposal", "conditional", "infeasible", "manual_only"
    ] = "infeasible"


class SensitivityResult(KillswitchModel):
    """Lightweight deterministic sensitivity check across policy weight profiles."""

    stable: StrictBool
    baseline_winner_id: str | None = None
    profile_winners: dict[str, str | None] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class ContainmentAnalysisResult(KillswitchModel):
    """Complete explainable containment analysis and optional approval-ready proposal."""

    incident_id: str = Field(min_length=1)
    finding_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    blast_radius: BlastRadiusResult
    recommended_option: ContainmentOption | None = None
    ranked_feasible_options: list[ContainmentOption] = Field(default_factory=list)
    conditional_options: list[ContainmentOption] = Field(default_factory=list)
    infeasible_options: list[ContainmentOption] = Field(default_factory=list)
    evaluated_strategies: list[EvaluatedStrategy] = Field(default_factory=list)
    sensitivity: SensitivityResult
    proposal: ContainmentProposal | None = None
    verification_checklist: list[str] = Field(default_factory=list)
    manual_review_required: StrictBool = True
    reason_codes: list[ContainmentReasonCode] = Field(default_factory=list)
    ranking_explanation: str = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)
    is_fixture_only: StrictBool = False
