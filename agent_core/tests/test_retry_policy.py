"""Category H: Bounded retry, error classification, and unknown write reconciliation tests."""

from __future__ import annotations

import pytest
from agent_core.context import FixedClock
from agent_core.retry_policy import (
    RetryClassification,
    RetryPolicyConfig,
    classify_error,
    execute_with_retry,
)
from shared.exceptions import (
    IntegrationUnavailableError,
    InvalidApprovalError,
    TelemetryUnavailableError,
)


@pytest.mark.unit
def test_retry_error_classification_rules() -> None:
    assert classify_error(TelemetryUnavailableError("Metrics lag")) == RetryClassification.RETRYABLE
    assert classify_error(InvalidApprovalError("Bad hash")) == RetryClassification.NON_RETRYABLE
    assert (
        classify_error(TimeoutError("Flagsmith write timed out"), is_privileged_write=True)
        == RetryClassification.RECONCILIATION_REQUIRED
    )
    assert (
        classify_error(IntegrationUnavailableError("503 during write"), is_privileged_write=True)
        == RetryClassification.RECONCILIATION_REQUIRED
    )


@pytest.mark.unit
async def test_execute_with_retry_handles_transient_exhaustion_and_deadline(
    fixed_clock: FixedClock,
) -> None:
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        fixed_clock.advance(delay)

    # 1. Transient failure succeeds on 3rd attempt
    attempts = 0

    async def flaky_read() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise IntegrationUnavailableError("Temporary 503")
        return "ok"

    val, res = await execute_with_retry(
        operation_id="op_read_1",
        fn=flaky_read,
        config=RetryPolicyConfig(max_attempts=3, initial_backoff_seconds=1.0),
        clock=fixed_clock,
        sleep_fn=fake_sleep,
    )
    assert val == "ok"
    assert res.succeeded is True
    assert res.attempts_made == 3
    assert sleeps == [1.0, 2.0]

    # 2. Privileged write timeout triggers RECONCILIATION_REQUIRED with 1 attempt (no blind retry)
    write_attempts = 0

    async def timed_out_write() -> str:
        nonlocal write_attempts
        write_attempts += 1
        raise TimeoutError("Write timed out")

    val2, res2 = await execute_with_retry(
        operation_id="op_write_1",
        fn=timed_out_write,
        config=RetryPolicyConfig(max_attempts=3),
        clock=fixed_clock,
        sleep_fn=fake_sleep,
        is_privileged_write=True,
    )
    assert val2 is None
    assert write_attempts == 1
    assert res2.reconciliation_required is True
    assert res2.classification == RetryClassification.RECONCILIATION_REQUIRED

    # 3. Exhaustion bounded by max_attempts
    async def always_unavailable() -> str:
        raise TelemetryUnavailableError("Always down")

    val3, res3 = await execute_with_retry(
        operation_id="op_exhaust_1",
        fn=always_unavailable,
        config=RetryPolicyConfig(max_attempts=2, initial_backoff_seconds=0.5),
        clock=fixed_clock,
        sleep_fn=fake_sleep,
    )
    assert val3 is None
    assert res3.exhausted is True
    assert res3.attempts_made == 2
