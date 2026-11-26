"""Central provider-independent LLMGateway orchestrating every AI model invocation.

Enforces configuration validation, model routing, versioned prompts, token budgeting,
bounded transport retries, bounded output repair loops, strict schema validation,
optional read-only tool validation, bounded caching, and sanitized observability.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel
from shared.contracts import LLMProvider as SharedLLMProviderProtocol
from shared.contracts import LLMRequest as SharedLLMRequest
from shared.enums import AIProviderErrorCategory, AITaskType, DataClassification
from shared.logging_config import redact_mapping, redact_text
from shared.schemas import ModelMetadata
from shared.serialization import sha256_canonical

from agent_core.context import Clock, SystemClock
from agent_core.llm.cache import CacheKeyInput, SafeAIResultCache
from agent_core.llm.error_mapping import NormalizedLLMError, normalize_provider_error
from agent_core.llm.observability import (
    AIExecutionRecord,
    AIMetricsCollector,
    ModelPricingConfig,
    estimate_execution_cost,
    log_ai_execution,
    utc_elapsed_ms,
)
from agent_core.llm.provider import GatewayLLMProvider
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.request import GatewayLLMRequest
from agent_core.llm.response import GatewayLLMResponse
from agent_core.llm.routing import ModelRouter, TaskRouteTarget
from agent_core.llm.structured_output import (
    SemanticValidatorFn,
    format_validation_errors_for_repair,
    validate_structured_response,
)
from agent_core.llm.token_budget import TokenBudgetManager, TokenBudgetPolicy
from agent_core.prompts.registry import LoadedPrompt, PromptRegistry
from agent_core.retry_policy import RetryPolicyConfig, execute_with_retry
from agent_core.tools.executor import BoundedToolExecutor
from agent_core.tools.policy import ToolPolicyConfig, ToolPolicyEnforcer
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.schemas import ToolInvocationAudit

SchemaT = TypeVar("SchemaT", bound=BaseModel)


@dataclass
class ProviderCircuitBreaker:
    """Lightweight closed / open / half-open circuit breaker per provider."""

    failure_threshold: int = 3
    recovery_timeout_seconds: float = 30.0
    _consecutive_failures: dict[str, int] = field(default_factory=dict)
    _opened_at_epoch: dict[str, float] = field(default_factory=dict)

    def get_state(
        self, provider_name: str, *, now_epoch: float
    ) -> Literal["closed", "open", "half_open"]:
        opened = self._opened_at_epoch.get(provider_name)
        if opened is None:
            return "closed"
        if (now_epoch - opened) >= self.recovery_timeout_seconds:
            return "half_open"
        return "open"

    def record_success(self, provider_name: str) -> None:
        self._consecutive_failures.pop(provider_name, None)
        self._opened_at_epoch.pop(provider_name, None)

    def record_failure(self, provider_name: str, *, now_epoch: float) -> None:
        count = self._consecutive_failures.get(provider_name, 0) + 1
        self._consecutive_failures[provider_name] = count
        if count >= self.failure_threshold:
            self._opened_at_epoch[provider_name] = now_epoch


@dataclass
class GatewayStructuredResult(Generic[SchemaT]):
    """Complete result returned by ``LLMGateway.generate_structured``."""

    parsed: SchemaT
    response: GatewayLLMResponse
    execution_record: AIExecutionRecord
    model_metadata: ModelMetadata
    tool_audits: list[ToolInvocationAudit] = field(default_factory=list)
    repair_attempts: int = 0
    cache_hit: bool = False


class LLMGateway:
    """Single centralized gateway for all AI reasoning tasks in Killswitch X."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        router: ModelRouter,
        prompt_registry: PromptRegistry | None = None,
        token_budget_manager: TokenBudgetManager | None = None,
        tool_registry: ToolRegistry | None = None,
        tool_policy_config: ToolPolicyConfig | None = None,
        cache: SafeAIResultCache | None = None,
        metrics: AIMetricsCollector | None = None,
        pricing_table: dict[tuple[str, str], ModelPricingConfig] | None = None,
        retry_config: RetryPolicyConfig | None = None,
        max_repair_attempts: int = 1,
        circuit_breaker: ProviderCircuitBreaker | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.registry = registry
        self.router = router
        self.prompt_registry = prompt_registry or PromptRegistry()
        self.token_budget = token_budget_manager or TokenBudgetManager()
        self.tool_registry = tool_registry
        self.tool_policy_config = tool_policy_config or ToolPolicyConfig()
        self.cache = cache
        self.metrics = metrics or AIMetricsCollector()
        self.pricing_table = pricing_table
        self.retry_config = retry_config or RetryPolicyConfig(
            max_attempts=3,
            initial_backoff_seconds=0.05,
            backoff_multiplier=2.0,
            max_backoff_seconds=0.5,
            operation_timeout_seconds=30.0,
            overall_deadline_seconds=45.0,
        )
        self.max_repair_attempts = max(0, max_repair_attempts)
        self.circuit_breaker = circuit_breaker
        self._clock = clock or SystemClock()

    def _build_cache_key(
        self,
        *,
        task: AITaskType,
        incident_id: str,
        authorization_scope: str,
        context: dict[str, Any],
        context_hash: str,
        prompt: LoadedPrompt,
        target: TaskRouteTarget,
        response_model_name: str,
    ) -> CacheKeyInput:
        finding_obj = context.get("finding", {})
        ev_refs = context.get("evidence_references", [])
        ev_hashes = tuple(
            sorted(
                str(e.get("content_hash", e.get("artifact_id", "")))
                for e in ev_refs
                if isinstance(e, dict)
            )
        )
        return CacheKeyInput(
            task_type=task,
            incident_id=incident_id,
            authorization_scope=authorization_scope,
            finding_hash=sha256_canonical(finding_obj),
            evidence_hashes=ev_hashes,
            context_hash=context_hash,
            source_revision=context.get("repository_revision"),
            environment=context.get("environment"),
            prompt_version=prompt.metadata.version,
            prompt_hash=prompt.metadata.content_hash,
            provider=target.provider_name,
            model=target.model_name,
            schema_version=response_model_name,
        )

    async def generate_structured(
        self,
        task: AITaskType | str,
        context: dict[str, Any],
        response_model: type[SchemaT],
        *,
        incident_id: str | None = None,
        correlation_id: str | None = None,
        prompt_version: str | None = None,
        allowed_tools: list[str] | None = None,
        authorized_source_paths: set[str] | None = None,
        semantic_validator: SemanticValidatorFn | None = None,
        data_classification: DataClassification = DataClassification.RESTRICTED_SECURITY,
        authorization_scope: str = "default",
        temperature: float | None = 0.0,
        max_output_tokens: int | None = None,
        timeout_seconds: float | None = None,
        total_deadline_seconds: float | None = None,
        context_hash: str | None = None,
        system_prompt_override: str | None = None,
        user_message_override: str | None = None,
    ) -> GatewayStructuredResult[SchemaT]:
        """Execute a bounded, schema-validated AI request through centralized controls."""
        task_enum = task if isinstance(task, AITaskType) else AITaskType(task)
        req_id = f"lreq_{uuid.uuid4().hex[:16]}"
        req_started_at = self._clock.now()
        sanitized_context = redact_mapping(context)
        resolved_context_hash = context_hash or sha256_canonical(sanitized_context)
        context_json = json.dumps(sanitized_context, sort_keys=True, ensure_ascii=False)

        prompt = self.prompt_registry.get_prompt(task_enum, version=prompt_version)
        sys_instructions = system_prompt_override or prompt.system_instructions
        user_message = user_message_override or prompt.render_user_message(
            context_json=context_json
        )
        schema_dict = response_model.model_json_schema()

        tool_defs = []
        allowed_tool_set: set[str] | None = None
        if allowed_tools and self.tool_registry is not None:
            allowed_tool_set = set(allowed_tools)
            for td in self.tool_registry.list_definitions(task_type=task_enum):
                if td.name in allowed_tool_set:
                    tool_defs.append(td.to_function_declaration())

        targets, max_total_attempts = self.router.resolve_candidate_targets(
            task_type=task_enum,
            data_classification=data_classification,
            require_tools=bool(allowed_tools),
        )

        # Optional cache lookup against primary target
        primary_target = targets[0]
        if self.cache is not None and incident_id is not None:
            cache_key = self._build_cache_key(
                task=task_enum,
                incident_id=incident_id,
                authorization_scope=authorization_scope,
                context=sanitized_context,
                context_hash=resolved_context_hash,
                prompt=prompt,
                target=primary_target,
                response_model_name=response_model.__name__,
            )
            cached = self.cache.get(cache_key, now=req_started_at)
            if isinstance(cached, GatewayStructuredResult):
                cached_rec = cached.execution_record.model_copy(
                    update={"cache_hit": True, "request_id": req_id}
                )
                cached_meta = cached.model_metadata.model_copy(update={"cache_hit": True})
                self.metrics.record_execution(cached_rec)
                log_ai_execution(cached_rec)
                return GatewayStructuredResult(
                    parsed=cached.parsed,
                    response=cached.response,
                    execution_record=cached_rec,
                    model_metadata=cached_meta,
                    tool_audits=cached.tool_audits,
                    repair_attempts=cached.repair_attempts,
                    cache_hit=True,
                )

        effective_budget = TokenBudgetManager(
            TokenBudgetPolicy(
                max_input_tokens=min(
                    self.token_budget.policy.max_input_tokens, primary_target.max_input_tokens
                ),
                max_output_tokens=min(
                    self.token_budget.policy.max_output_tokens, primary_target.max_output_tokens
                ),
            )
        )

        last_error: NormalizedLLMError | None = None
        remaining_attempts_budget = max_total_attempts
        overall_deadline = total_deadline_seconds or self.retry_config.overall_deadline_seconds
        tool_audits: list[ToolInvocationAudit] = []

        tool_enforcer: ToolPolicyEnforcer | None = None
        tool_executor: BoundedToolExecutor | None = None
        if self.tool_registry is not None and incident_id is not None:
            tool_enforcer = ToolPolicyEnforcer(
                incident_id=incident_id,
                task_type=task_enum,
                registry=self.tool_registry,
                config=self.tool_policy_config,
                allowed_tool_names=allowed_tool_set,
                authorized_source_paths=authorized_source_paths,
                metrics=self.metrics,
            )
            tool_executor = BoundedToolExecutor(
                incident_id=incident_id,
                task_type=task_enum,
                registry=self.tool_registry,
                policy=tool_enforcer,
            )

        for target in targets:
            if remaining_attempts_budget <= 0:
                break
            now_epoch = self._clock.now().timestamp()
            if (
                self.circuit_breaker is not None
                and self.circuit_breaker.get_state(target.provider_name, now_epoch=now_epoch)
                == "open"
            ):
                last_error = NormalizedLLMError(
                    f"Circuit breaker open for provider {target.provider_name!r}.",
                    category=AIProviderErrorCategory.TEMPORARY_UNAVAILABLE,
                    provider=target.provider_name,
                )
                continue

            provider = self.registry.get(target.provider_name)
            caps = provider.get_capabilities()

            # Check token budget before transport invocation (only once we know provider).
            sys_tokens = await effective_budget.count_text(
                sys_instructions, provider=provider, model_name=target.model_name
            )
            ctx_tokens = await effective_budget.count_text(
                user_message, provider=provider, model_name=target.model_name
            )
            effective_budget.assert_input_within_budget(
                system_tokens=sys_tokens.tokens,
                context_tokens=ctx_tokens.tokens,
                provider_name=target.provider_name,
            )

            eff_out_tokens = effective_budget.clamp_output_tokens(
                max_output_tokens, provider_max=caps.max_output_tokens
            )
            eff_timeout = timeout_seconds or self.retry_config.operation_timeout_seconds
            eff_temp = temperature if caps.supports_temperature else None

            gateway_req = GatewayLLMRequest(
                request_id=req_id,
                incident_id=incident_id,
                correlation_id=correlation_id,
                task_type=task_enum,
                provider_name=target.provider_name,
                model_name=target.model_name,
                system_instructions=sys_instructions,
                structured_context=sanitized_context,
                user_message=user_message,
                expected_response_schema=schema_dict if caps.supports_native_schema else None,
                temperature=eff_temp,
                max_output_tokens=eff_out_tokens,
                timeout_seconds=eff_timeout,
                allowed_tools=tool_defs,
                prompt_version=prompt.metadata.version,
                prompt_hash=prompt.metadata.content_hash,
                context_hash=resolved_context_hash,
                data_classification=data_classification,
                metadata={"response_model": response_model.__name__},
            )

            elapsed_so_far = (self._clock.now() - req_started_at).total_seconds()
            rem_deadline = max(0.05, overall_deadline - elapsed_so_far)
            target_retry_cfg = self.retry_config.model_copy(
                update={
                    "max_attempts": remaining_attempts_budget,
                    "operation_timeout_seconds": min(eff_timeout, rem_deadline),
                    "overall_deadline_seconds": rem_deadline,
                }
            )

            async def _invoke_once(
                prov_ref: GatewayLLMProvider = provider,
                req_to_send: GatewayLLMRequest = gateway_req,
            ) -> GatewayLLMResponse:
                return await prov_ref.generate(req_to_send)

            try:
                raw_resp, retry_res = await execute_with_retry(
                    operation_id=req_id,
                    fn=_invoke_once,
                    config=target_retry_cfg,
                    clock=self._clock,
                )
            except asyncio.CancelledError:
                raise

            remaining_attempts_budget -= retry_res.attempts_made
            if raw_resp is None:
                if retry_res.error_code and "TIMEOUT" in retry_res.error_code:
                    self.metrics.timeout_count += 1
                    cat = AIProviderErrorCategory.TIMEOUT
                else:
                    cat = AIProviderErrorCategory.TEMPORARY_UNAVAILABLE
                self.metrics.provider_failures += 1
                if self.circuit_breaker is not None:
                    self.circuit_breaker.record_failure(
                        target.provider_name, now_epoch=self._clock.now().timestamp()
                    )
                last_error = NormalizedLLMError(
                    retry_res.error_message or "Provider request failed.",
                    category=cat,
                    provider=target.provider_name,
                )
                continue

            if self.circuit_breaker is not None:
                self.circuit_breaker.record_success(target.provider_name)

            # Handle optional requested tool calls OUTSIDE the model via bounded policy
            active_resp = raw_resp
            if active_resp.requested_tool_calls:
                for tcall in active_resp.requested_tool_calls:
                    if tool_executor is None:
                        self.metrics.tool_authorization_rejections += 1
                        tool_audits.append(
                            ToolInvocationAudit(
                                call_id=tcall.call_id,
                                tool_name=tcall.tool_name,
                                incident_id=incident_id or "unknown_incident",
                                task_type=task_enum,
                                allowed=False,
                                executed=False,
                                reason_code="TOOLS_NOT_ENABLED",
                                sanitized_message=(
                                    f"Tool request {tcall.tool_name!r} rejected: no tools enabled."
                                ),
                            )
                        )
                    else:
                        exec_res = await tool_executor.execute(tcall, current_round=1)
                        tool_audits.append(exec_res.audit)

            # Parse + validate + bounded repair loop
            repairs_used = 0
            validation_failures = 0
            current_response = active_resp.model_copy(
                update={"attempt_count": retry_res.attempts_made}
            )
            parsed_model: SchemaT | None = None
            last_validation_exc: Exception | None = None

            for repair_idx in range(self.max_repair_attempts + 1):
                try:
                    parsed_model = validate_structured_response(
                        current_response,
                        response_model,
                        semantic_validator=semantic_validator,
                    )
                    break
                except Exception as exc:
                    validation_failures += 1
                    self.metrics.structured_output_validation_failures += 1
                    last_validation_exc = exc
                    if isinstance(exc, NormalizedLLMError) and (
                        exc.category == AIProviderErrorCategory.CONTENT_RESTRICTION
                    ):
                        break
                    if repair_idx >= self.max_repair_attempts:
                        break
                    elapsed_repair = (self._clock.now() - req_started_at).total_seconds()
                    if elapsed_repair >= overall_deadline:
                        break

                    repairs_used += 1
                    err_summary = redact_text(format_validation_errors_for_repair(exc))
                    repair_msg = prompt.render_repair_message(
                        validation_errors=err_summary,
                        context_json=context_json,
                    )
                    repair_req = gateway_req.model_copy(
                        update={
                            "request_id": f"lreq_{uuid.uuid4().hex[:16]}",
                            "user_message": repair_msg,
                        }
                    )
                    try:
                        current_response = await asyncio.wait_for(
                            provider.generate(repair_req),
                            timeout=max(0.1, overall_deadline - elapsed_repair),
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as repair_exc:
                        last_validation_exc = normalize_provider_error(
                            repair_exc, provider=target.provider_name
                        )
                        break

            if parsed_model is None:
                last_error = normalize_provider_error(
                    last_validation_exc
                    or NormalizedLLMError(
                        "Structured validation failed after bounded repair attempts.",
                        category=AIProviderErrorCategory.RESPONSE_VALIDATION_FAILURE,
                        provider=target.provider_name,
                    ),
                    provider=target.provider_name,
                )
                break

            finished_at = self._clock.now()
            latency_ms = current_response.latency_ms
            if latency_ms is None:
                latency_ms = utc_elapsed_ms(req_started_at, finished_at)
            cost_usd, cost_status = estimate_execution_cost(
                provider=target.provider_name,
                model_name=target.model_name,
                input_tokens=current_response.input_tokens,
                output_tokens=current_response.output_tokens,
                pricing_table=self.pricing_table,
            )
            exec_rec = AIExecutionRecord(
                request_id=req_id,
                incident_id=incident_id,
                correlation_id=correlation_id,
                task_type=task_enum,
                provider=target.provider_name,
                model=target.model_name,
                prompt_version=prompt.metadata.version,
                prompt_hash=prompt.metadata.content_hash,
                context_hash=resolved_context_hash,
                request_timestamp=req_started_at,
                response_timestamp=finished_at,
                latency_ms=latency_ms,
                input_tokens=current_response.input_tokens,
                output_tokens=current_response.output_tokens,
                attempt_count=retry_res.attempts_made + repairs_used,
                tool_calls=len(tool_audits),
                validation_failures=validation_failures,
                repair_attempts=repairs_used,
                fallback_used=False,
                cache_hit=False,
                synthetic_origin=current_response.synthetic_origin,
                final_status="ok",
                cost_usd=cost_usd,
                cost_status=cost_status,
            )
            self.metrics.record_execution(exec_rec)
            log_ai_execution(exec_rec)

            model_meta = ModelMetadata(
                provider=target.provider_name,
                model_name=target.model_name,
                prompt_version=prompt.metadata.version,
                latency_ms=latency_ms,
                token_usage=current_response.total_tokens,
                prompt_hash=prompt.metadata.content_hash,
                context_hash=resolved_context_hash,
                input_tokens=current_response.input_tokens,
                output_tokens=current_response.output_tokens,
                attempt_count=retry_res.attempts_made + repairs_used,
                cache_hit=False,
                fallback_used=False,
                synthetic_origin=current_response.synthetic_origin,
            )
            gw_result: GatewayStructuredResult[SchemaT] = GatewayStructuredResult(
                parsed=parsed_model,
                response=current_response,
                execution_record=exec_rec,
                model_metadata=model_meta,
                tool_audits=tool_audits,
                repair_attempts=repairs_used,
                cache_hit=False,
            )
            if self.cache is not None and incident_id is not None:
                c_key = self._build_cache_key(
                    task=task_enum,
                    incident_id=incident_id,
                    authorization_scope=authorization_scope,
                    context=sanitized_context,
                    context_hash=resolved_context_hash,
                    prompt=prompt,
                    target=target,
                    response_model_name=response_model.__name__,
                )
                self.cache.put(c_key, gw_result, now=finished_at, is_valid_result=True)
            return gw_result

        raise last_error or NormalizedLLMError(
            "All configured LLM provider attempts failed.",
            category=AIProviderErrorCategory.TEMPORARY_UNAVAILABLE,
            provider=primary_target.provider_name,
        )


class GatewaySharedLLMProvider(SharedLLMProviderProtocol):
    """Bridge satisfying ``shared.contracts.LLMProvider`` over centralized ``LLMGateway``."""

    def __init__(self, gateway: LLMGateway) -> None:
        self._gateway = gateway

    async def generate_structured(
        self,
        request: SharedLLMRequest,
        output_schema: type[SchemaT],
    ) -> tuple[SchemaT, ModelMetadata]:
        try:
            task = AITaskType(request.task_name)
        except ValueError:
            task = AITaskType.INVESTIGATION
        res = await self._gateway.generate_structured(
            task,
            {"bounded_context_text": request.user_context[: request.max_context_chars]},
            output_schema,
            correlation_id=request.correlation_id,
            temperature=request.temperature,
            system_prompt_override=request.system_prompt,
        )
        return res.parsed, res.model_metadata
