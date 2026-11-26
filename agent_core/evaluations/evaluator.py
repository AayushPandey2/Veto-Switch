"""Reproducible AI evaluation runner separating fixture and live-provider runs (Section 31)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import Field
from shared.enums import AITaskType, FindingStatus
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    Finding,
    KillswitchModel,
    UtcDatetime,
    VerificationResult,
)

from agent_core.evaluations.metrics import (
    HUMAN_EVALUATION_RUBRIC,
    CaseEvaluationResult,
    EvaluationMetricsSummary,
    aggregate_evaluation_metrics,
    check_fallback_correctness,
)
from agent_core.intelligence.context_builder import InvestigationContextBuilder
from agent_core.intelligence.investigation_context import (
    AdvisoryContextItem,
    DependencyMetadataItem,
    InvestigationInputBundle,
    SourceExcerpt,
)
from agent_core.investigator import Investigator
from agent_core.llm.gateway import LLMGateway
from agent_core.llm.observability import AIMetricsCollector
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.providers.fixture import FixtureBehaviorMode, FixtureLLMProvider
from agent_core.llm.routing import ModelRouter
from agent_core.llm.token_budget import TokenBudgetManager, TokenBudgetPolicy
from agent_core.prompts.registry import PromptRegistry
from agent_core.retry_policy import RetryPolicyConfig
from agent_core.tools.registry import build_default_investigation_tool_registry

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "datasets" / "investigation_cases.json"


class EvaluationRunReport(KillswitchModel):
    """Complete JSON-serializable evaluation run report with provenance & limitations."""

    run_id: str
    evaluated_at: UtcDatetime = Field(default_factory=utc_now)
    dataset_version: str
    synthetic_dataset: bool
    evaluation_mode: Literal["offline_fixture", "live_provider"]
    provider_name: str
    model_name: str
    prompt_version: str
    prompt_hash: str
    fallback_enabled: bool
    metrics: EvaluationMetricsSummary
    case_results: list[CaseEvaluationResult]
    known_limitations: list[str]
    human_review_rubric: dict[str, str] = Field(
        default_factory=lambda: dict(HUMAN_EVALUATION_RUBRIC)
    )


def load_evaluation_dataset(path: Path | str = DEFAULT_DATASET_PATH) -> dict[str, Any]:
    """Load and validate structural presence of the evaluation dataset JSON."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), list):
        raise ValueError(f"Invalid evaluation dataset structure at {path}.")
    return raw


def _build_bundle_from_case(case: dict[str, Any]) -> InvestigationInputBundle:
    finding = Finding.model_validate(case["finding"])
    artifacts = [
        ArtifactReference.model_validate(
            {
                "content_type": "application/json",
                "size_bytes": 128,
                **a,
            }
        )
        for a in case.get("artifacts", [])
    ]
    verifications = [
        VerificationResult.model_validate(v) for v in case.get("verification_results", [])
    ]

    excerpts: list[SourceExcerpt] = []
    for raw_ex in case.get("source_excerpts", []):
        ex_dict = dict(raw_ex)
        mult = ex_dict.pop("repeat_noise_multiplier", None)
        if isinstance(mult, int) and mult > 1:
            ex_dict["code_excerpt"] = ex_dict["code_excerpt"] + (
                "# filler_line_for_budget_test\n" * mult
            )
        excerpts.append(SourceExcerpt.model_validate(ex_dict))

    deps = [DependencyMetadataItem.model_validate(d) for d in case.get("dependencies", [])]
    advs = [AdvisoryContextItem.model_validate(a) for a in case.get("advisories", [])]
    manifest: dict[str, Any] = {}
    if case.get("large_manifest_items"):
        manifest["routes"] = [
            {
                "route": f"/extra_{i}",
                "owner": f"team_{i}",
                "notes": "verbose optional metadata " * 5,
            }
            for i in range(int(case["large_manifest_items"]))
        ]

    return InvestigationInputBundle(
        finding=finding,
        verification_results=verifications,
        verification_environments=dict(case.get("verification_environments", {})),
        evidence_artifacts=artifacts,
        artifact_environments=dict(case.get("artifact_environments", {})),
        source_excerpts=excerpts,
        dependencies=deps,
        advisories=advs,
        application_manifest_summary=manifest,
    )


async def run_evaluation_suite(
    *,
    dataset_path: Path | str = DEFAULT_DATASET_PATH,
    evaluation_mode: Literal["offline_fixture", "live_provider"] = "offline_fixture",
    gateway: LLMGateway | None = None,
    prompt_version: str | None = None,
    case_ids: set[str] | None = None,
) -> EvaluationRunReport:
    """Execute evaluation cases and return a structured ``EvaluationRunReport``."""
    dataset = load_evaluation_dataset(dataset_path)
    prompt_reg = PromptRegistry()
    loaded_prompt = prompt_reg.get_prompt(AITaskType.INVESTIGATION, version=prompt_version)

    results: list[CaseEvaluationResult] = []
    provider_label = "offline_fixture"
    model_label = "fixture-investigator-v1"

    for case in dataset["cases"]:
        cid = str(case["case_id"])
        cat = str(case["category"])
        if case_ids is not None and cid not in case_ids:
            results.append(
                CaseEvaluationResult(
                    case_id=cid,
                    category=cat,
                    skipped=True,
                    skip_reason="filtered_out_by_case_ids",
                )
            )
            continue

        bundle = _build_bundle_from_case(case)
        max_in_tok = int(case.get("max_input_tokens_override", 6000))
        budget_mgr = TokenBudgetManager(TokenBudgetPolicy(max_input_tokens=max_in_tok))
        ctx_builder = InvestigationContextBuilder(budget_policy=budget_mgr.policy)

        if evaluation_mode == "offline_fixture":
            mode_str = case.get("override_mode_alias") or case.get(
                "scripted_provider_mode", "valid"
            )
            scripted_mode = FixtureBehaviorMode(mode_str)
            metrics = AIMetricsCollector()
            fix_prov = FixtureLLMProvider(default_mode=scripted_mode)
            reg = ProviderRegistry()
            reg.register(fix_prov)
            router = ModelRouter(
                registry=reg,
                default_provider="offline_fixture",
                default_model="fixture-investigator-v1",
                default_max_input_tokens=max_in_tok,
            )
            case_gw = LLMGateway(
                registry=reg,
                router=router,
                prompt_registry=prompt_reg,
                token_budget_manager=budget_mgr,
                tool_registry=build_default_investigation_tool_registry(),
                cache=None,
                metrics=metrics,
                retry_config=RetryPolicyConfig(
                    max_attempts=1,
                    initial_backoff_seconds=0.0,
                    max_backoff_seconds=0.0,
                    operation_timeout_seconds=10.0,
                    overall_deadline_seconds=15.0,
                ),
                max_repair_attempts=0,
            )
        else:
            if gateway is None:
                results.append(
                    CaseEvaluationResult(
                        case_id=cid,
                        category=cat,
                        skipped=True,
                        skip_reason="no_live_gateway_configured",
                    )
                )
                continue
            case_gw = gateway
            target = case_gw.router.get_route(AITaskType.INVESTIGATION).primary
            provider_label = target.provider_name
            model_label = target.model_name

        inv = Investigator(
            llm_gateway=case_gw,
            context_builder=ctx_builder,
            metrics=case_gw.metrics,
        )
        exec_res = await inv.investigate_bundle(bundle, prompt_version=prompt_version)
        summary = exec_res.summary
        grounding = exec_res.grounding_report

        allowed_ids = exec_res.context.allowed_evidence_ids()
        cited_top = summary.evidence_ids
        valid_ref_ratio = (
            sum(1 for eid in cited_top if eid in allowed_ids) / len(cited_top)
            if cited_top
            else (1.0 if not allowed_ids else 0.0)
        )
        total_claims = len(summary.grounded_facts) + len(summary.technical_interpretations)
        claims_with_refs = sum(
            1
            for c in [*summary.grounded_facts, *summary.technical_interpretations]
            if c.evidence_ids
        )
        claim_cov = (claims_with_refs / total_claims) if total_claims > 0 else 1.0

        expected_status = FindingStatus(case["expected_finding_status"])
        status_preserved = summary.finding_status == expected_status
        expected_next = str(case["expected_next_action"])
        next_ok = summary.recommended_next_action == expected_next
        expect_unc = bool(case.get("expect_uncertainty", False))
        unc_ok = (bool(summary.uncertainties or summary.missing_evidence) if expect_unc else True)

        combined_prose = (
            summary.executive_summary + "\n" + summary.technical_explanation
        ).lower()
        forbidden_hits = [
            phrase
            for phrase in case.get("forbidden_claims", [])
            if str(phrase).lower() in combined_prose
        ]

        tool_attempted = sum(1 for a in exec_res.tool_audits if not a.allowed)
        tool_executed_bad = sum(1 for a in exec_res.tool_audits if not a.allowed and a.executed)
        fb_ok = check_fallback_correctness(
            fallback_used=summary.fallback_used,
            expected_status=expected_status,
            actual_status=summary.finding_status,
            reasoning_source=summary.reasoning_source,
            unknown_refs_count=len(grounding.unknown_references),
            uncertainties=summary.uncertainties,
            missing_evidence=summary.missing_evidence,
        )

        ctx_audit = exec_res.context.audit
        reduction_tokens = (
            max(0, ctx_audit.pre_reduction_tokens - ctx_audit.post_reduction_tokens)
            if ctx_audit is not None
            else 0
        )
        in_tok = exec_res.execution_record.input_tokens if exec_res.execution_record else None
        out_tok = exec_res.execution_record.output_tokens if exec_res.execution_record else None

        case_passed = (
            grounding.overall_valid
            and status_preserved
            and next_ok
            and unc_ok
            and not forbidden_hits
            and tool_executed_bad == 0
            and fb_ok
            and (summary.fallback_used == bool(case.get("expect_fallback", False)))
        )

        results.append(
            CaseEvaluationResult(
                case_id=cid,
                category=cat,
                skipped=False,
                schema_valid=True,
                evidence_reference_valid_ratio=round(valid_ref_ratio, 4),
                claim_grounding_coverage_ratio=round(claim_cov, 4),
                factual_contradictions_count=len(grounding.direct_factual_contradictions),
                hallucinated_identifiers_count=len(grounding.hallucinated_identifiers),
                forbidden_claim_violations=forbidden_hits,
                status_preserved=status_preserved,
                uncertainty_recognized=unc_ok,
                next_action_accurate=next_ok,
                tool_violations_attempted=tool_attempted,
                tool_violations_executed=tool_executed_bad,
                fallback_used=summary.fallback_used,
                expected_fallback=bool(case.get("expect_fallback", False)),
                fallback_correct=fb_ok,
                reasoning_source=summary.reasoning_source.value,
                context_duration_ms=exec_res.context_duration_ms,
                provider_duration_ms=exec_res.provider_duration_ms,
                validation_duration_ms=exec_res.validation_duration_ms,
                total_duration_ms=exec_res.total_duration_ms,
                input_tokens=in_tok,
                output_tokens=out_tok,
                context_reduction_tokens=reduction_tokens,
                requests_made=exec_res.model_requests_made,
                passed=case_passed,
            )
        )

    agg = aggregate_evaluation_metrics(results, evaluation_mode=evaluation_mode)
    limitations: list[str] = [
        (
            "All dataset cases are synthetic fixtures designed to verify grounding, policy, "
            "and fallback invariants."
        ),
    ]
    if evaluation_mode == "offline_fixture":
        limitations.append(
            "OFFLINE FIXTURE EVALUATION ONLY: Live LLM reasoning quality has NOT been empirically "
            "evaluated because no live provider credentials were used."
        )

    return EvaluationRunReport(
        run_id=f"eval_{uuid.uuid4().hex[:12]}",
        dataset_version=str(dataset["dataset_version"]),
        synthetic_dataset=bool(dataset.get("synthetic_dataset", True)),
        evaluation_mode=evaluation_mode,
        provider_name=provider_label,
        model_name=model_label,
        prompt_version=loaded_prompt.metadata.version,
        prompt_hash=loaded_prompt.metadata.content_hash,
        fallback_enabled=True,
        metrics=agg,
        case_results=results,
        known_limitations=limitations,
    )
