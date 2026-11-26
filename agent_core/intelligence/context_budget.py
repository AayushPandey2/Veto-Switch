"""Deterministic token-budget reduction engine preserving mandatory evidence (Section 14)."""

from __future__ import annotations

from shared.enums import AIProviderErrorCategory

from agent_core.intelligence.investigation_context import (
    ExcludedContextItem,
    InvestigationContext,
)
from agent_core.llm.error_mapping import NormalizedLLMError
from agent_core.llm.token_budget import TokenBudgetPolicy, estimate_tokens


def enforce_context_budget(
    context: InvestigationContext,
    *,
    policy: TokenBudgetPolicy,
    has_tools: bool = False,
) -> tuple[InvestigationContext, int, int, list[str]]:
    """Apply Section 14 reduction rules without dropping mandatory evidence.

    Reduction order:
        1. Drop optional/non-mandatory manifest metadata.
        2. Compact feature registry summary beyond first 10 flags.
        3. Trim lower-priority redundant source excerpts & verbose summaries.
        4. Compact advisory text & dependency metadata.
        5. Trim non-mandatory extra evidence references only if mandatory remain intact.
        6. Fail explicitly with ``TOKEN_BUDGET_EXCEEDED`` if mandatory context cannot fit.
    """
    budget_limit = policy.available_context_tokens(has_tools=has_tools)
    pre_tokens = estimate_tokens(context.to_prompt_payload()).tokens
    if pre_tokens <= budget_limit:
        return context, pre_tokens, pre_tokens, []

    working = context.model_copy(deep=True)
    truncation_reasons: list[str] = []

    def _current_tokens() -> int:
        return estimate_tokens(working.to_prompt_payload()).tokens

    # Step 1: Drop verbose application manifest summary
    if _current_tokens() > budget_limit and working.application_manifest_summary:
        working.application_manifest_summary = {}
        truncation_reasons.append("dropped_optional_manifest_summary")

    # Step 2: Compact declared feature registry summary
    if _current_tokens() > budget_limit and len(working.declared_feature_registry_summary) > 10:
        omitted = len(working.declared_feature_registry_summary) - 10
        working.declared_feature_registry_summary = working.declared_feature_registry_summary[:10]
        truncation_reasons.append(f"compacted_feature_registry_summary({omitted}_omitted)")

    # Step 3: Compact long evidence summaries (preserving artifact IDs & provenance!)
    if _current_tokens() > budget_limit and working.evidence_summaries:
        changed = False
        for k, v in list(working.evidence_summaries.items()):
            if len(v) > 200:
                working.evidence_summaries[k] = v[:197] + "..."
                changed = True
        if changed:
            truncation_reasons.append("compacted_verbose_evidence_summaries")

    # Step 4: Drop trailing secondary source excerpts one by one, keeping >=1 if present
    while _current_tokens() > budget_limit and len(working.bounded_source_excerpts) > 1:
        dropped = working.bounded_source_excerpts.pop()
        working.excluded_items.append(
            ExcludedContextItem(
                item_id=dropped.file_id,
                item_kind="source_excerpt",
                reason_code="BUDGET_EXCEEDED",
                reason="Lower-priority source excerpt omitted to fit token budget.",
            )
        )
        truncation_reasons.append(f"dropped_secondary_source_excerpt({dropped.file_id})")

    # Trim remaining single source excerpt if very large
    if _current_tokens() > budget_limit and working.bounded_source_excerpts:
        primary_ex = working.bounded_source_excerpts[0]
        if len(primary_ex.code_excerpt) > 800:
            primary_ex.code_excerpt = primary_ex.code_excerpt[:780] + "\n# ...[TRUNCATED]"
            truncation_reasons.append(f"truncated_source_excerpt({primary_ex.file_id})")

    # Step 5: Compact advisories & secondary dependencies
    if _current_tokens() > budget_limit and working.advisory_context:
        for adv in working.advisory_context:
            if len(adv.summary) > 160:
                adv.summary = adv.summary[:157] + "..."
        truncation_reasons.append("compacted_advisory_summaries")

    while _current_tokens() > budget_limit and len(working.dependency_metadata) > 2:
        dep_dropped = working.dependency_metadata.pop()
        truncation_reasons.append(f"dropped_secondary_dependency({dep_dropped.dependency_name})")

    if _current_tokens() > budget_limit and len(working.bounded_source_excerpts) == 1:
        ex0 = working.bounded_source_excerpts.pop()
        working.excluded_items.append(
            ExcludedContextItem(
                item_id=ex0.file_id,
                item_kind="source_excerpt",
                reason_code="BUDGET_EXCEEDED",
                reason="Source excerpt omitted to preserve mandatory evidence inside tight budget.",
            )
        )
        working.missing_information.append(
            "source_excerpt_omitted_due_to_token_budget"
        )
        truncation_reasons.append(f"omitted_source_excerpt_for_mandatory_budget({ex0.file_id})")

    # Mandatory check: if even mandatory finding + verification + evidence references exceed budget,
    # NEVER silently drop mandatory evidence — fail explicitly!
    post_tokens = _current_tokens()
    if post_tokens > budget_limit:
        raise NormalizedLLMError(
            f"Mandatory investigation context ({post_tokens} estimated tokens) exceeds "
            f"configured input budget ({budget_limit} available context tokens).",
            category=AIProviderErrorCategory.TOKEN_BUDGET_EXCEEDED,
            provider="context_budget",
            context={
                "pre_reduction_tokens": pre_tokens,
                "post_reduction_tokens": post_tokens,
                "available_context_tokens": budget_limit,
            },
        )

    return working, pre_tokens, post_tokens, truncation_reasons
