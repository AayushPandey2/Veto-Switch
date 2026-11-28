"""Sanitized AI observability records, metric counters, and optional cost estimation."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt
from shared.enums import AITaskType
from shared.logging_config import get_logger, log_structured, redact_mapping
from shared.schemas import KillswitchModel, UtcDatetime

_LOGGER = get_logger("killswitch.ai.observability")


class ModelPricingConfig(KillswitchModel):
    """Explicitly configured per-1K-token pricing (never invented by default)."""

    provider: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    input_usd_per_1k: float = Field(ge=0.0)
    output_usd_per_1k: float = Field(ge=0.0)


class AIExecutionRecord(KillswitchModel):
    """Sanitized telemetry metadata captured per AI model or fallback execution."""

    request_id: str = Field(min_length=4, max_length=128)
    incident_id: str | None = None
    correlation_id: str | None = None
    task_type: AITaskType
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    prompt_hash: str | None = None
    context_hash: str | None = None
    request_timestamp: UtcDatetime
    response_timestamp: UtcDatetime
    latency_ms: float | None = Field(default=None, ge=0.0)
    input_tokens: StrictInt | None = Field(default=None, ge=0)
    output_tokens: StrictInt | None = Field(default=None, ge=0)
    attempt_count: StrictInt = Field(default=1, ge=0)
    tool_calls: StrictInt = Field(default=0, ge=0)
    validation_failures: StrictInt = Field(default=0, ge=0)
    repair_attempts: StrictInt = Field(default=0, ge=0)
    fallback_used: StrictBool = False
    fallback_reason: str | None = None
    cache_hit: StrictBool = False
    synthetic_origin: StrictBool = False
    final_status: str = Field(min_length=1)
    sanitized_error: str | None = None
    cost_usd: float | None = Field(default=None, ge=0.0)
    cost_status: Literal["actual", "estimated", "unknown"] = "unknown"


def estimate_execution_cost(
    *,
    provider: str,
    model_name: str,
    input_tokens: int | None,
    output_tokens: int | None,
    pricing_table: dict[tuple[str, str], ModelPricingConfig] | None,
) -> tuple[float | None, Literal["actual", "estimated", "unknown"]]:
    """Estimate cost ONLY when verified pricing config AND token counts are available."""
    if not pricing_table or input_tokens is None or output_tokens is None:
        return None, "unknown"
    cfg = pricing_table.get((provider.lower(), model_name))
    if cfg is None:
        return None, "unknown"
    cost = (input_tokens / 1000.0) * cfg.input_usd_per_1k + (
        output_tokens / 1000.0
    ) * cfg.output_usd_per_1k
    return round(cost, 8), "estimated"


class AIMetricsCollector:
    """In-memory metric accumulator covering all Section 26 AI observability counters."""

    def __init__(self) -> None:
        self.total_investigation_requests: int = 0
        self.successful_llm_investigations: int = 0
        self.deterministic_fallbacks: int = 0
        self.provider_failures: int = 0
        self.timeout_count: int = 0
        self.structured_output_validation_failures: int = 0
        self.grounding_validation_failures: int = 0
        self.unsupported_evidence_references: int = 0
        self.tool_authorization_rejections: int = 0
        self.context_budget_failures: int = 0
        self.cache_hits: int = 0
        self.total_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.unknown_token_responses: int = 0
        self.latency_ms_samples: list[float] = []
        self.records: list[AIExecutionRecord] = []

    def record_execution(self, rec: AIExecutionRecord) -> None:
        self.records.append(rec)
        if rec.latency_ms is not None:
            self.latency_ms_samples.append(rec.latency_ms)
        if rec.input_tokens is not None:
            self.total_input_tokens += rec.input_tokens
        if rec.output_tokens is not None:
            self.total_output_tokens += rec.output_tokens
        if rec.input_tokens is None or rec.output_tokens is None:
            self.unknown_token_responses += 1
        if rec.cache_hit:
            self.cache_hits += 1

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable summary of recorded AI metrics."""
        return {
            "total_investigation_requests": self.total_investigation_requests,
            "successful_llm_investigations": self.successful_llm_investigations,
            "deterministic_fallbacks": self.deterministic_fallbacks,
            "provider_failures": self.provider_failures,
            "timeout_count": self.timeout_count,
            "structured_output_validation_failures": self.structured_output_validation_failures,
            "grounding_validation_failures": self.grounding_validation_failures,
            "unsupported_evidence_references": self.unsupported_evidence_references,
            "tool_authorization_rejections": self.tool_authorization_rejections,
            "context_budget_failures": self.context_budget_failures,
            "cache_hits": self.cache_hits,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "unknown_token_responses": self.unknown_token_responses,
            "latency_samples_count": len(self.latency_ms_samples),
        }


def log_ai_execution(
    record: AIExecutionRecord,
    *,
    logger: logging.Logger | None = None,
) -> None:
    """Emit sanitized metadata-only log entry (NEVER logs prompts, source code, or secrets)."""
    target_logger = logger or _LOGGER
    payload = redact_mapping(
        {
            "request_id": record.request_id,
            "task_type": record.task_type.value,
            "provider": record.provider,
            "model": record.model,
            "prompt_version": record.prompt_version,
            "prompt_hash": record.prompt_hash,
            "context_hash": record.context_hash,
            "latency_ms": record.latency_ms,
            "input_tokens": record.input_tokens,
            "output_tokens": record.output_tokens,
            "attempt_count": record.attempt_count,
            "repair_attempts": record.repair_attempts,
            "fallback_used": record.fallback_used,
            "cache_hit": record.cache_hit,
            "synthetic_origin": record.synthetic_origin,
            "final_status": record.final_status,
            "cost_status": record.cost_status,
        }
    )
    log_structured(
        target_logger,
        logging.INFO,
        f"AI execution completed with status={record.final_status}",
        incident_id=record.incident_id,
        correlation_id=record.correlation_id,
        event_type="ai_execution",
        operation_status=record.final_status,
        context=payload,
    )


def utc_elapsed_ms(start: datetime, end: datetime) -> float:
    """Compute non-negative elapsed milliseconds between two UTC datetimes."""
    return round(max(0.0, (end - start).total_seconds() * 1000.0), 3)
