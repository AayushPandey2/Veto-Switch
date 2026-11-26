"""AI Security Investigator implementing the 12-step Section 20 reasoning workflow."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

from pydantic import Field, StrictInt
from shared.enums import (
    AIProviderErrorCategory,
    AITaskType,
    DataClassification,
    EvidenceProvenance,
    InvestigationStatus,
    VulnerabilityCategory,
)
from shared.exceptions import (
    ConfigurationError,
    ContractValidationError,
    LLMProviderError,
    LLMResponseValidationError,
)
from shared.schemas import (
    ArtifactReference,
    Finding,
    GroundingValidationReport,
    InvestigationSummary,
    KillswitchModel,
)
from shared.serialization import sha256_canonical

from agent_core.context import InvestigatorAgent
from agent_core.intelligence.context_builder import InvestigationContextBuilder
from agent_core.intelligence.fallback import DeterministicFallbackInvestigator
from agent_core.intelligence.investigation_context import (
    ContextAuditMetadata,
    InvestigationContext,
    InvestigationInputBundle,
    VerificationContextSummary,
)
from agent_core.intelligence.response_validator import (
    InvestigationResponseValidator,
    RawInvestigationOutput,
    check_raw_investigation_semantics,
)
from agent_core.llm.error_mapping import NormalizedLLMError
from agent_core.llm.gateway import LLMGateway
from agent_core.llm.observability import AIExecutionRecord, AIMetricsCollector
from agent_core.tools.schemas import ToolInvocationAudit

InvestigationOutcomeCategory = Literal[
    "successful_llm_investigation",
    "successful_deterministic_fallback",
    "partial_investigation",
    "additional_evidence_required",
    "manual_review_required",
    "infrastructure_failure",
]


class InvestigationExecutionResult(KillswitchModel):
    """Complete auditable Investigator result including timing, grounding, and dashboard view."""

    summary: InvestigationSummary
    context: InvestigationContext
    grounding_report: GroundingValidationReport
    execution_record: AIExecutionRecord | None = None
    tool_audits: list[ToolInvocationAudit] = Field(default_factory=list)
    outcome_status: InvestigationOutcomeCategory
    context_duration_ms: float = Field(default=0.0, ge=0.0)
    provider_duration_ms: float | None = Field(default=None, ge=0.0)
    validation_duration_ms: float = Field(default=0.0, ge=0.0)
    total_duration_ms: float = Field(default=0.0, ge=0.0)
    model_requests_made: StrictInt = Field(default=0, ge=0)

    def to_dashboard_payload(self) -> dict[str, Any]:
        """Serialize a frontend-ready JSON payload (Section 34) without raw prose parsing."""
        return format_investigation_dashboard_payload(self)


def format_investigation_dashboard_payload(
    result: InvestigationExecutionResult | InvestigationSummary,
) -> dict[str, Any]:
    """Build Section 34 frontend-ready structure with presentation classification labels."""
    if isinstance(result, InvestigationExecutionResult):
        summary = result.summary
        grounding = result.grounding_report
        rec = result.execution_record
    else:
        summary = result
        grounding = result.grounding_report or GroundingValidationReport(
            total_claims=len(summary.grounded_facts) + len(summary.technical_interpretations),
            claims_with_supplied_references=0,
            reference_checks_passed=bool(summary.evidence_ids),
            contradiction_checks_passed=True,
            semantic_review_required=True,
            overall_valid=bool(summary.evidence_ids),
        )
        rec = None

    meta = summary.model_metadata
    if summary.fallback_used:
        source_label = "deterministic_fallback"
    elif summary.reasoning_source == EvidenceProvenance.REFERENCE_FIXTURE or (
        meta is not None and meta.synthetic_origin
    ):
        source_label = "synthetic_fixture"
    else:
        source_label = "llm"

    verified_facts_view = [
        {
            "claim_id": c.claim_id,
            "statement": c.statement,
            "badge": "verified_fact",
            "classification": c.classification.value,
            "validation_status": c.validation_status.value,
            "evidence_ids": c.evidence_ids,
        }
        for c in summary.grounded_facts
    ] or [
        {
            "claim_id": f"legacy_{idx + 1}",
            "statement": text,
            "badge": "verified_fact",
            "classification": "observed",
            "validation_status": "validated",
            "evidence_ids": summary.evidence_ids,
        }
        for idx, text in enumerate(summary.verified_facts)
    ]

    interps_view = [
        {
            "claim_id": c.claim_id,
            "statement": c.statement,
            "badge": "inferred_interpretation",
            "classification": c.classification.value,
            "validation_status": c.validation_status.value,
            "evidence_ids": c.evidence_ids,
            "limitations": c.limitations,
        }
        for c in summary.technical_interpretations
    ]

    impacts_view = [
        {
            "description": imp.description,
            "badge": "verified_impact" if imp.verified else "potential_impact",
            "verified": imp.verified,
            "limitations": imp.limitations,
        }
        for imp in summary.potential_impacts
    ]

    return {
        "incident_id": summary.incident_id,
        "investigation_id": summary.investigation_id,
        "finding_id": summary.finding_id,
        "investigation": {
            "status": summary.investigation_status.value,
            "source": source_label,
            "summary": summary.executive_summary,
            "technical_explanation": summary.technical_explanation,
            "finding_status": (
                summary.finding_status.value if summary.finding_status is not None else "unknown"
            ),
            "affected_component": (
                summary.affected_components[0] if summary.affected_components else "unknown"
            ),
            "affected_components": list(summary.affected_components),
            "affected_route": summary.affected_route,
            "evidence_support_level": summary.evidence_support_level.value,
            "verified_facts": verified_facts_view,
            "technical_interpretations": interps_view,
            "potential_impacts": impacts_view,
            "assumptions": list(summary.assumptions),
            "uncertainties": list(summary.uncertainties),
            "missing_evidence": list(summary.missing_evidence),
            "evidence_references": list(summary.evidence_ids),
            "recommended_next_action": summary.recommended_next_action,
        },
        "validation": {
            "schema_valid": True,
            "reference_checks_passed": grounding.reference_checks_passed,
            "contradiction_checks_passed": grounding.contradiction_checks_passed,
            "semantic_review_required": grounding.semantic_review_required,
            "requires_manual_review": summary.requires_manual_review,
            "fallback_response": summary.fallback_used,
            "unverified_claims_present": bool(interps_view or not grounding.overall_valid),
            "notes": list(grounding.notes),
        },
        "execution": {
            "provider": meta.provider if meta else "deterministic_fallback",
            "model": meta.model_name if meta else "unconfigured",
            "prompt_version": summary.prompt_version or (meta.prompt_version if meta else None),
            "prompt_hash": summary.prompt_hash,
            "context_hash": summary.context_hash,
            "latency_ms": rec.latency_ms if rec else (meta.latency_ms if meta else None),
            "input_tokens": rec.input_tokens if rec else (meta.input_tokens if meta else None),
            "output_tokens": rec.output_tokens if rec else (meta.output_tokens if meta else None),
            "cache_hit": rec.cache_hit if rec else (meta.cache_hit if meta else False),
            "fallback_used": summary.fallback_used,
            "fallback_reason": summary.fallback_reason,
            "synthetic_origin": meta.synthetic_origin if meta else False,
        },
    }


def _minimal_fallback_context(finding: Finding, *, reason: str) -> InvestigationContext:
    ver_sum = VerificationContextSummary(
        reproduction_outcome="not_run",
        environment=finding.environment,
        tested_revision=finding.repository_revision,
    )
    ctx = InvestigationContext(
        incident_id=finding.incident_id,
        finding=finding,
        affected_route=finding.affected_route,
        affected_component=finding.affected_component,
        repository_revision=finding.repository_revision,
        environment=finding.environment,
        verification_summary=ver_sum,
        known_limitations=[reason],
        missing_information=["bounded_context_fit_for_llm"],
        data_provenance=[finding.provenance],
    )
    h = sha256_canonical(ctx.to_prompt_payload())
    return ctx.model_copy(
        update={
            "context_hash": h,
            "audit": ContextAuditMetadata(context_hash=h),
        }
    )


class Investigator(InvestigatorAgent):
    """Evidence-grounded AI Investigator adhering to ``agent_core.context.InvestigatorAgent``."""

    def __init__(
        self,
        *,
        llm_gateway: LLMGateway | None,
        context_builder: InvestigationContextBuilder | None = None,
        response_validator: InvestigationResponseValidator | None = None,
        fallback: DeterministicFallbackInvestigator | None = None,
        fallback_enabled: bool = True,
        metrics: AIMetricsCollector | None = None,
    ) -> None:
        self._gateway = llm_gateway
        self._context_builder = context_builder or InvestigationContextBuilder()
        self._validator = response_validator or InvestigationResponseValidator()
        self._fallback = fallback or DeterministicFallbackInvestigator()
        self._fallback_enabled = fallback_enabled
        self._metrics = metrics or (
            llm_gateway.metrics if llm_gateway is not None else AIMetricsCollector()
        )

    async def investigate(
        self,
        finding: Finding,
        evidence_artifacts: list[ArtifactReference],
    ) -> InvestigationSummary:
        """Satisfy ``agent_core.context.InvestigatorAgent`` protocol."""
        bundle = InvestigationInputBundle(
            finding=finding,
            evidence_artifacts=evidence_artifacts,
        )
        res = await self.investigate_bundle(bundle)
        return res.summary

    async def investigate_bundle(
        self,
        bundle: InvestigationInputBundle,
        *,
        correlation_id: str | None = None,
        prompt_version: str | None = None,
        allowed_tools: list[str] | None = None,
    ) -> InvestigationExecutionResult:
        """Execute the complete 12-step Section 20 investigation workflow."""
        total_start = time.monotonic()
        self._metrics.total_investigation_requests += 1

        # Step 1 & 2 — Validate finding & establish trusted incident context
        finding = bundle.finding
        if not finding.incident_id or not finding.finding_id:
            raise ContractValidationError("Finding requires non-empty incident_id and finding_id.")

        # Step 4 — Build bounded model context (10-stage pipeline)
        ctx_start = time.monotonic()
        try:
            context = self._context_builder.build(bundle, has_tools=bool(allowed_tools))
            budget_exceeded_reason: str | None = None
        except NormalizedLLMError as exc:
            if exc.category != AIProviderErrorCategory.TOKEN_BUDGET_EXCEEDED:
                raise
            self._metrics.context_budget_failures += 1
            budget_exceeded_reason = exc.message
            context = _minimal_fallback_context(finding, reason=exc.message)
        ctx_ms = round((time.monotonic() - ctx_start) * 1000.0, 3)

        prompt_ver = prompt_version
        prompt_hash: str | None = None
        if self._gateway is not None:
            loaded_prompt = self._gateway.prompt_registry.get_prompt(
                AITaskType.INVESTIGATION, version=prompt_version
            )
            prompt_ver = loaded_prompt.metadata.version
            prompt_hash = loaded_prompt.metadata.content_hash

        # Step 3 & 5 & 6 — Check if context budget failed OR gateway missing OR category=other hint
        if budget_exceeded_reason is not None:
            return self._run_fallback(
                context=context,
                reason=budget_exceeded_reason,
                original_provider=None,
                original_model=None,
                prompt_version=prompt_ver,
                prompt_hash=prompt_hash,
                ctx_ms=ctx_ms,
                total_start=total_start,
            )

        if self._gateway is None:
            if not self._fallback_enabled:
                raise ConfigurationError(
                    "LLMGateway is unavailable and deterministic fallback is disabled."
                )
            return self._run_fallback(
                context=context,
                reason="no_llm_gateway_configured",
                original_provider=None,
                original_model=None,
                prompt_version=prompt_ver,
                prompt_hash=prompt_hash,
                ctx_ms=ctx_ms,
                total_start=total_start,
            )

        provider_start = time.monotonic()
        try:
            gw_result = await self._gateway.generate_structured(
                AITaskType.INVESTIGATION,
                context.to_prompt_payload(),
                RawInvestigationOutput,
                incident_id=finding.incident_id,
                correlation_id=correlation_id,
                prompt_version=prompt_ver,
                allowed_tools=allowed_tools,
                authorized_source_paths=bundle.authorized_source_paths,
                semantic_validator=check_raw_investigation_semantics,
                data_classification=(
                    DataClassification.SENSITIVE_SOURCE
                    if context.bounded_source_excerpts
                    else DataClassification.RESTRICTED_SECURITY
                ),
                context_hash=context.context_hash,
            )
        except asyncio.CancelledError:
            raise
        except (LLMProviderError, LLMResponseValidationError, ConfigurationError) as exc:
            if isinstance(exc, NormalizedLLMError) and (
                exc.category == AIProviderErrorCategory.TOKEN_BUDGET_EXCEEDED
            ):
                self._metrics.context_budget_failures += 1
            if not self._fallback_enabled:
                raise
            return self._run_fallback(
                context=context,
                reason=f"{type(exc).__name__}: {exc.error_code}",
                original_provider=getattr(exc, "provider", None),
                original_model=None,
                prompt_version=prompt_ver,
                prompt_hash=prompt_hash,
                ctx_ms=ctx_ms,
                total_start=total_start,
            )
        provider_ms = round((time.monotonic() - provider_start) * 1000.0, 3)

        # Step 7, 8, 9 — Validate schema, claim-level grounding & uncertainty
        val_start = time.monotonic()
        try:
            summary, grounding_report, _uncertainty = self._validator.validate(
                raw_output=gw_result.parsed,
                context=context,
                model_metadata=gw_result.model_metadata,
                prompt_version=prompt_ver or gw_result.model_metadata.prompt_version,
                prompt_hash=prompt_hash or (gw_result.model_metadata.prompt_hash or ""),
                synthetic_origin=gw_result.model_metadata.synthetic_origin,
            )
        except LLMResponseValidationError as exc:
            self._metrics.grounding_validation_failures += 1
            unknown_refs = exc.context.get("unknown_references", [])
            if isinstance(unknown_refs, list):
                self._metrics.unsupported_evidence_references += len(unknown_refs)
            if not self._fallback_enabled:
                raise
            has_anomalies = finding.category == VulnerabilityCategory.OTHER or bool(
                exc.context.get("contradictions")
            )
            return self._run_fallback(
                context=context,
                reason=f"validation_or_grounding_failure: {exc.message}",
                original_provider=gw_result.model_metadata.provider,
                original_model=gw_result.model_metadata.model_name,
                prompt_version=prompt_ver,
                prompt_hash=prompt_hash,
                ctx_ms=ctx_ms,
                provider_ms=provider_ms,
                total_start=total_start,
                execution_record=gw_result.execution_record,
                tool_audits=gw_result.tool_audits,
                has_untrusted_anomalies=has_anomalies,
            )

        val_ms = round((time.monotonic() - val_start) * 1000.0, 3)
        self._metrics.successful_llm_investigations += 1
        outcome_status = _derive_outcome_status(summary)

        return InvestigationExecutionResult(
            summary=summary,
            context=context,
            grounding_report=grounding_report,
            execution_record=gw_result.execution_record,
            tool_audits=gw_result.tool_audits,
            outcome_status=outcome_status,
            context_duration_ms=ctx_ms,
            provider_duration_ms=provider_ms,
            validation_duration_ms=val_ms,
            total_duration_ms=round((time.monotonic() - total_start) * 1000.0, 3),
            model_requests_made=gw_result.execution_record.attempt_count,
        )

    def _run_fallback(
        self,
        *,
        context: InvestigationContext,
        reason: str,
        original_provider: str | None,
        original_model: str | None,
        prompt_version: str | None,
        prompt_hash: str | None,
        ctx_ms: float,
        total_start: float,
        provider_ms: float | None = None,
        execution_record: AIExecutionRecord | None = None,
        tool_audits: list[ToolInvocationAudit] | None = None,
        has_untrusted_anomalies: bool = False,
    ) -> InvestigationExecutionResult:
        val_start = time.monotonic()
        self._metrics.deterministic_fallbacks += 1
        summary, grounding = self._fallback.build_fallback(
            context=context,
            fallback_reason=reason,
            original_provider=original_provider,
            original_model=original_model,
            prompt_version=prompt_version,
            prompt_hash=prompt_hash,
            has_untrusted_anomalies=has_untrusted_anomalies,
        )
        val_ms = round((time.monotonic() - val_start) * 1000.0, 3)
        return InvestigationExecutionResult(
            summary=summary,
            context=context,
            grounding_report=grounding,
            execution_record=execution_record,
            tool_audits=tool_audits or [],
            outcome_status="successful_deterministic_fallback",
            context_duration_ms=ctx_ms,
            provider_duration_ms=provider_ms,
            validation_duration_ms=val_ms,
            total_duration_ms=round((time.monotonic() - total_start) * 1000.0, 3),
            model_requests_made=execution_record.attempt_count if execution_record else 0,
        )


def _derive_outcome_status(summary: InvestigationSummary) -> InvestigationOutcomeCategory:
    if summary.fallback_used:
        return "successful_deterministic_fallback"
    if summary.investigation_status == InvestigationStatus.MANUAL_REVIEW_REQUIRED:
        return "manual_review_required"
    if summary.investigation_status == InvestigationStatus.INSUFFICIENT_EVIDENCE:
        return "additional_evidence_required"
    if summary.investigation_status == InvestigationStatus.PARTIAL:
        return "partial_investigation"
    return "successful_llm_investigation"
