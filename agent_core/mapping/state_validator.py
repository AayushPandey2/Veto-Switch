"""Runtime feature-state observation validation with injectable clock and freshness policy."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from shared.enums import (
    EvidenceProvenance,
    FeatureObservationStatus,
    MappingReasonCode,
)
from shared.identifiers import ensure_utc
from shared.schemas import FeatureState

from agent_core.mapping.models import FreshnessPolicy, StateValidationResult

DEFAULT_FRESHNESS_POLICY = FreshnessPolicy()

_LIVE_REJECTED_STATE_PROVENANCE: frozenset[EvidenceProvenance] = frozenset(
    {
        EvidenceProvenance.REFERENCE_FIXTURE,
        EvidenceProvenance.SYNTHETIC_TELEMETRY,
        EvidenceProvenance.LLM_INTERPRETATION,
    }
)


def validate_feature_states(
    feature_name: str,
    observed_features: Sequence[FeatureState],
    *,
    environment: str,
    evaluation_time: datetime,
    fixture_mode: bool = False,
    policy: FreshnessPolicy | None = None,
    targeting_config: dict[str, Any] | None = None,
) -> StateValidationResult:
    """Validate runtime ``FeatureState`` snapshots for ``feature_name``."""
    cfg = policy or DEFAULT_FRESHNESS_POLICY
    eval_utc = ensure_utc(evaluation_time)

    matching = [fs for fs in observed_features if fs.feature_name == feature_name]
    if not matching:
        return StateValidationResult(
            feature_name=feature_name,
            observation_status=FeatureObservationStatus.UNAVAILABLE,
            observed_enabled=None,
            fresh=False,
            consistent=True,
            action_eligible=False,
            requires_verification=True,
            reason_codes=[MappingReasonCode.FEATURE_STATE_UNAVAILABLE],
            limitations=[f"No runtime FeatureState observation provided for {feature_name!r}."],
        )

    env_matches = [fs for fs in matching if fs.environment == environment]
    if not env_matches:
        envs = sorted({fs.environment for fs in matching})
        return StateValidationResult(
            feature_name=feature_name,
            observation_status=FeatureObservationStatus.UNAVAILABLE,
            observed_enabled=None,
            fresh=False,
            consistent=False,
            action_eligible=False,
            requires_verification=True,
            reason_codes=[MappingReasonCode.ENVIRONMENT_MISMATCH],
            limitations=[
                f"FeatureState environment(s) {envs} do not match target {environment!r}."
            ],
        )

    # Sort deterministically by observed_at descending, then state_version, then feature_id
    ordered = sorted(
        env_matches,
        key=lambda fs: (ensure_utc(fs.observed_at), fs.state_version or "", fs.feature_id),
        reverse=True,
    )

    # Detect conflicting observed states across snapshots
    observed_values = {
        fs.enabled
        for fs in ordered
        if fs.observation_status == FeatureObservationStatus.OBSERVED
    }
    observed_statuses = {fs.observation_status for fs in ordered}
    if len(observed_values) > 1 or (
        len(observed_statuses) > 1 and FeatureObservationStatus.OBSERVED in observed_statuses
    ):
        return StateValidationResult(
            feature_name=feature_name,
            observation_status=FeatureObservationStatus.UNKNOWN,
            observed_enabled=None,
            fresh=False,
            consistent=False,
            action_eligible=False,
            requires_verification=True,
            reason_codes=[MappingReasonCode.FEATURE_STATE_CONFLICT],
            limitations=[
                f"Conflicting FeatureState observations recorded for {feature_name!r}."
            ],
        )

    latest = ordered[0]
    reason_codes: list[MappingReasonCode] = []
    limitations: list[str] = []

    if latest.observation_status != FeatureObservationStatus.OBSERVED:
        code = (
            MappingReasonCode.FEATURE_STATE_UNKNOWN
            if latest.observation_status == FeatureObservationStatus.UNKNOWN
            else MappingReasonCode.FEATURE_STATE_UNAVAILABLE
        )
        return StateValidationResult(
            feature_name=feature_name,
            observation_status=latest.observation_status,
            observed_enabled=None,
            state_version=latest.state_version,
            fresh=False,
            consistent=True,
            action_eligible=False,
            requires_verification=True,
            reason_codes=[code],
            limitations=[
                f"Feature {feature_name!r} observation_status={latest.observation_status.value!r}; "
                "cannot assume disabled."
            ],
            observed_at=ensure_utc(latest.observed_at),
            provenance=latest.observation_source,
        )

    if not fixture_mode and latest.observation_source in _LIVE_REJECTED_STATE_PROVENANCE:
        reason_codes.append(MappingReasonCode.FIXTURE_ONLY_EVIDENCE)
        limitations.append(
            f"FeatureState provenance {latest.observation_source.value!r} cannot authorize "
            "live action."
        )

    obs_utc = ensure_utc(latest.observed_at)
    delta_seconds = (eval_utc - obs_utc).total_seconds()
    fresh = True
    if delta_seconds < -cfg.max_future_skew_seconds:
        fresh = False
        reason_codes.append(MappingReasonCode.FEATURE_STATE_FUTURE_TIMESTAMP)
        limitations.append(
            f"FeatureState timestamp {obs_utc.isoformat()} exceeds future skew tolerance "
            f"({cfg.max_future_skew_seconds}s)."
        )
    elif delta_seconds > cfg.max_age_seconds:
        fresh = False
        reason_codes.append(MappingReasonCode.FEATURE_STATE_STALE)
        limitations.append(
            f"FeatureState observation is stale ({int(delta_seconds)}s > {cfg.max_age_seconds}s)."
        )

    targeting = dict(latest.segment_targeting)
    if targeting_config:
        targeting.update(targeting_config)
    targeting_uncertain = bool(targeting.get("segments") or targeting.get("percentage") is not None)
    if targeting_uncertain:
        reason_codes.append(MappingReasonCode.SEGMENT_TARGETING_UNCERTAINTY)
        limitations.append(
            "Segment or percentage targeting rules detected; global boolean does not guarantee "
            "uniform behavior across all users."
        )

    already_disabled = latest.enabled is False
    if already_disabled:
        reason_codes.append(MappingReasonCode.FEATURE_ALREADY_DISABLED)
        limitations.append(
            f"Feature {feature_name!r} is already observed disabled; no redundant mutation "
            "recommended, but post-containment verification is still required."
        )
    else:
        reason_codes.append(MappingReasonCode.FEATURE_STATE_OBSERVED)

    action_eligible = (
        fresh
        and MappingReasonCode.FIXTURE_ONLY_EVIDENCE not in reason_codes
        and not already_disabled
    )

    return StateValidationResult(
        feature_name=feature_name,
        observation_status=latest.observation_status,
        observed_enabled=latest.enabled,
        state_version=latest.state_version,
        fresh=fresh,
        consistent=True,
        already_disabled=already_disabled,
        segment_targeting_uncertain=targeting_uncertain,
        action_eligible=action_eligible,
        requires_verification=True,
        reason_codes=sorted(set(reason_codes), key=lambda c: c.value),
        limitations=limitations,
        observed_at=obs_utc,
        provenance=latest.observation_source,
    )
