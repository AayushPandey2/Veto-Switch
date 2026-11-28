"""Bounded retry, timeout, and error-classification policies for orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime
from enum import StrEnum
from typing import TypeVar

from pydantic import Field, StrictBool, StrictInt
from shared.exceptions import (
    AmbiguousMappingError,
    ConcurrencyConflictError,
    ContractValidationError,
    EvidenceNotFoundError,
    EvidenceValidationError,
    ExpiredApprovalError,
    IdempotencyConflictError,
    IntegrationUnavailableError,
    InvalidApprovalError,
    InvalidTransitionError,
    KillswitchError,
    PatchValidationError,
    TelemetryUnavailableError,
    TestRunnerError,
    UnauthorizedOperationError,
    UnknownFeatureError,
)
from shared.schemas import KillswitchModel, UtcDatetime

from agent_core.context import Clock, SystemClock

T = TypeVar("T")


class RetryClassification(StrEnum):
    """Deterministic classification of transient vs. non-retryable vs. reconcile errors."""

    RETRYABLE = "retryable"
    NON_RETRYABLE = "non_retryable"
    RECONCILIATION_REQUIRED = "reconciliation_required"


class RetryPolicyConfig(KillswitchModel):
    """Bounded retry and deadline configuration."""

    max_attempts: StrictInt = Field(default=3, ge=1, le=10)
    initial_backoff_seconds: float = Field(default=0.5, ge=0.0, le=60.0)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    max_backoff_seconds: float = Field(default=5.0, ge=0.0, le=120.0)
    operation_timeout_seconds: float = Field(default=10.0, gt=0.0, le=300.0)
    overall_deadline_seconds: float = Field(default=30.0, gt=0.0, le=600.0)


class RetryAttemptRecord(KillswitchModel):
    """Structured diagnostic record for each retry attempt."""

    operation_id: str = Field(min_length=1)
    attempt_number: StrictInt = Field(ge=1)
    failure_category: str = Field(min_length=1)
    classification: RetryClassification
    timestamp: UtcDatetime
    will_retry: StrictBool
    outcome: str = Field(min_length=1)


class RetryExecutionResult(KillswitchModel):
    """Outcome summary emitted after bounded retry execution."""

    operation_id: str = Field(min_length=1)
    succeeded: StrictBool
    attempts_made: StrictInt = Field(ge=1)
    classification: RetryClassification | None = None
    reconciliation_required: StrictBool = False
    exhausted: StrictBool = False
    error_code: str | None = None
    error_message: str | None = None
    attempt_records: list[RetryAttemptRecord] = Field(default_factory=list)


_NON_RETRYABLE_TYPES = (
    ContractValidationError,
    EvidenceValidationError,
    EvidenceNotFoundError,
    UnauthorizedOperationError,
    InvalidApprovalError,
    ExpiredApprovalError,
    InvalidTransitionError,
    UnknownFeatureError,
    AmbiguousMappingError,
    PatchValidationError,
    IdempotencyConflictError,
)

_RETRYABLE_TYPES = (
    IntegrationUnavailableError,
    TelemetryUnavailableError,
    TestRunnerError,
    ConcurrencyConflictError,
    TimeoutError,
)


def classify_error(
    exc: Exception,
    *,
    is_privileged_write: bool = False,
) -> RetryClassification:
    """Classify an exception into retryable, non-retryable, or reconciliation-required.

    Important:
        Timeouts or ambiguous transport failures during privileged external writes
        MUST NEVER trigger blind retries — they require state/operation
        reconciliation via readback first.
    """
    if isinstance(exc, _NON_RETRYABLE_TYPES):
        return RetryClassification.NON_RETRYABLE
    if is_privileged_write and isinstance(
        exc, (TimeoutError, asyncio.TimeoutError, IntegrationUnavailableError)
    ):
        return RetryClassification.RECONCILIATION_REQUIRED
    if isinstance(exc, KillswitchError):
        return RetryClassification.RETRYABLE if exc.retryable else RetryClassification.NON_RETRYABLE
    if isinstance(exc, _RETRYABLE_TYPES):
        return RetryClassification.RETRYABLE
    return RetryClassification.NON_RETRYABLE


async def execute_with_retry(
    *,
    operation_id: str,
    fn: Callable[[], Awaitable[T]],
    config: RetryPolicyConfig | None = None,
    clock: Clock | None = None,
    sleep_fn: Callable[[float], Awaitable[None]] | None = None,
    is_privileged_write: bool = False,
) -> tuple[T | None, RetryExecutionResult]:
    """Execute an async operation under bounded attempts, backoff, and overall deadline."""
    cfg = config or RetryPolicyConfig()
    clk: Clock = clock or SystemClock()
    sleeper = sleep_fn or asyncio.sleep

    start_time: datetime = clk.now()
    records: list[RetryAttemptRecord] = []
    backoff = cfg.initial_backoff_seconds

    for attempt in range(1, cfg.max_attempts + 1):
        elapsed = (clk.now() - start_time).total_seconds()
        if elapsed >= cfg.overall_deadline_seconds:
            return None, RetryExecutionResult(
                operation_id=operation_id,
                succeeded=False,
                attempts_made=max(1, attempt - 1),
                classification=RetryClassification.NON_RETRYABLE,
                exhausted=True,
                error_code="RETRY_DEADLINE_EXCEEDED",
                error_message="Overall operation retry deadline exceeded.",
                attempt_records=records,
            )

        try:
            result = await asyncio.wait_for(fn(), timeout=cfg.operation_timeout_seconds)
            records.append(
                RetryAttemptRecord(
                    operation_id=operation_id,
                    attempt_number=attempt,
                    failure_category="none",
                    classification=RetryClassification.RETRYABLE,
                    timestamp=clk.now(),
                    will_retry=False,
                    outcome="succeeded",
                )
            )
            return result, RetryExecutionResult(
                operation_id=operation_id,
                succeeded=True,
                attempts_made=attempt,
                attempt_records=records,
            )
        except Exception as exc:
            classification = classify_error(exc, is_privileged_write=is_privileged_write)
            error_code = exc.error_code if isinstance(exc, KillswitchError) else type(exc).__name__
            remaining_budget = (
                cfg.overall_deadline_seconds - (clk.now() - start_time).total_seconds()
            )
            can_retry = (
                classification == RetryClassification.RETRYABLE
                and attempt < cfg.max_attempts
                and remaining_budget > 0
            )
            records.append(
                RetryAttemptRecord(
                    operation_id=operation_id,
                    attempt_number=attempt,
                    failure_category=error_code,
                    classification=classification,
                    timestamp=clk.now(),
                    will_retry=can_retry,
                    outcome="retrying" if can_retry else classification.value,
                )
            )
            if not can_retry:
                return None, RetryExecutionResult(
                    operation_id=operation_id,
                    succeeded=False,
                    attempts_made=attempt,
                    classification=classification,
                    reconciliation_required=(
                        classification == RetryClassification.RECONCILIATION_REQUIRED
                    ),
                    exhausted=(
                        classification == RetryClassification.RETRYABLE
                        and attempt >= cfg.max_attempts
                    ),
                    error_code=error_code,
                    error_message=str(exc),
                    attempt_records=records,
                )

            delay = min(backoff, cfg.max_backoff_seconds, max(0.0, remaining_budget))
            await sleeper(delay)
            backoff = min(backoff * cfg.backoff_multiplier, cfg.max_backoff_seconds)

    return None, RetryExecutionResult(
        operation_id=operation_id,
        succeeded=False,
        attempts_made=cfg.max_attempts,
        exhausted=True,
        error_code="RETRY_EXHAUSTED",
        error_message="Retry attempts exhausted.",
        attempt_records=records,
    )
