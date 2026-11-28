"""Authoritative deterministic Vulnerability-to-Feature-Flag Mapping Engine.

This module implements ``FeatureMapperAgent`` with zero LLM calls, zero privileged
Flagsmith access, and zero mutation of input objects.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from shared.contracts import EvidenceRepository, FeatureStateReader
from shared.schemas import FeatureState, Finding, MappingResult, RouteFlagRegistry

from agent_core.context import Clock, FeatureMapperAgent, SystemClock
from agent_core.mapping.decision_policy import evaluate_mapping_decision
from agent_core.mapping.evidence_validator import validate_mapping_evidence
from agent_core.mapping.models import (
    FreshnessPolicy,
    MappingContext,
    MappingOutcome,
)


class DeterministicFlagMapper(FeatureMapperAgent):
    """Production-intended deterministic mapper implementing ``FeatureMapperAgent``."""

    def __init__(
        self,
        *,
        evidence_repository: EvidenceRepository | None = None,
        feature_state_reader: FeatureStateReader | None = None,
        clock: Clock | None = None,
        freshness_policy: FreshnessPolicy | None = None,
        fixture_mode: bool = False,
    ) -> None:
        self._evidence_repo = evidence_repository
        self._feature_reader = feature_state_reader
        self._clock: Clock = clock or SystemClock()
        self._freshness_policy = freshness_policy
        self._fixture_mode = fixture_mode

    async def map_with_diagnostics(
        self,
        finding: Finding,
        registry: RouteFlagRegistry,
        observed_features: Sequence[FeatureState] = (),
        *,
        context: MappingContext | None = None,
    ) -> MappingOutcome:
        """Map ``finding`` deterministically and return both ``MappingResult`` and diagnostics."""
        states = list(observed_features)
        if not states and context is not None and context.feature_states:
            states = list(context.feature_states)
        elif not states and self._feature_reader is not None:
            env = (
                (context.environment if context else None)
                or finding.environment
                or registry.environment
            )
            states = await self._feature_reader.list_declared_features(env)

        effective_ctx = (
            context.model_copy(
                update={
                    "feature_states": states,
                    "evaluation_timestamp": context.evaluation_timestamp,
                }
            )
            if context is not None
            else MappingContext(
                finding=finding,
                environment=finding.environment or registry.environment,
                application_revision=finding.repository_revision,
                registry_revision=registry.registry_version,
                feature_states=states,
                fixture_mode=self._fixture_mode,
                evaluation_timestamp=self._clock.now(),
            )
        )

        evidence_outcome = await validate_mapping_evidence(
            effective_ctx,
            evidence_repo=self._evidence_repo,
        )
        return evaluate_mapping_decision(
            effective_ctx,
            registry,
            evidence_outcome,
            freshness_policy=self._freshness_policy,
        )

    async def map_finding_to_flag(
        self,
        finding: Finding,
        registry: RouteFlagRegistry,
        observed_features: list[FeatureState],
        *,
        context: MappingContext | None = None,
    ) -> MappingResult:
        """``FeatureMapperAgent`` protocol entry point returning ``MappingResult``."""
        outcome = await self.map_with_diagnostics(
            finding,
            registry,
            observed_features,
            context=context,
        )
        return outcome.mapping_result


def map_finding_to_flags(
    finding: Finding,
    registry: RouteFlagRegistry,
    observed_features: Sequence[FeatureState] = (),
    *,
    context: MappingContext | None = None,
    fixture_mode: bool = True,
    freshness_policy: FreshnessPolicy | None = None,
) -> MappingResult:
    """Synchronous convenience wrapper for pure offline/unit deterministic mapping."""
    mapper = DeterministicFlagMapper(
        freshness_policy=freshness_policy,
        fixture_mode=context.fixture_mode if context is not None else fixture_mode,
    )
    return asyncio.run(
        mapper.map_finding_to_flag(
            finding,
            registry,
            list(observed_features),
            context=context,
        )
    )
