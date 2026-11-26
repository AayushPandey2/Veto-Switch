"""Reproducible offline synthetic incident simulations (Simulations A-H)."""

from __future__ import annotations

from agent_core.simulations.containment_failure import (
    run_containment_failure_simulation,
    run_duplicate_events_simulation,
)
from agent_core.simulations.recovery_failure import (
    run_patch_failure_simulation,
    run_rollout_failure_simulation,
)
from agent_core.simulations.rejected_incident import (
    run_invalid_or_expired_approval_simulation,
    run_rejected_containment_simulation,
)
from agent_core.simulations.successful_incident import (
    run_replay_parity_simulation,
    run_successful_incident_simulation,
)

__all__ = [
    "run_containment_failure_simulation",
    "run_duplicate_events_simulation",
    "run_invalid_or_expired_approval_simulation",
    "run_patch_failure_simulation",
    "run_rejected_containment_simulation",
    "run_replay_parity_simulation",
    "run_rollout_failure_simulation",
    "run_successful_incident_simulation",
]
