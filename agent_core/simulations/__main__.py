"""CLI entrypoint running all offline synthetic incident simulations (A-H)."""

from __future__ import annotations

import asyncio
import sys

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


async def run_all_simulations() -> int:
    """Execute all 8 synthetic simulations and print labeled summaries."""
    sim_a, _, _ = await run_successful_incident_simulation()
    sim_b = await run_rejected_containment_simulation()
    sim_c = await run_invalid_or_expired_approval_simulation()
    sim_d = await run_containment_failure_simulation()
    sim_e = await run_patch_failure_simulation()
    sim_f = await run_rollout_failure_simulation()
    sim_g = await run_duplicate_events_simulation()
    sim_h = await run_replay_parity_simulation()

    results = [sim_a, sim_b, sim_c, sim_d, sim_e, sim_f, sim_g, sim_h]
    for item in results:
        print(
            f"[SYNTHETIC SIMULATION] {item.name} | incident={item.incident_id} | "
            f"final_state={item.final_state.value} | version={item.incident_version} | "
            f"events={item.event_count} | replay_matched={item.replay_matched} | "
            f"notes={item.notes}"
        )
        assert item.is_synthetic
        assert item.replay_matched
    return 0


def main() -> int:
    return asyncio.run(run_all_simulations())


if __name__ == "__main__":
    sys.exit(main())
