"""10-stage intelligent context engineering pipeline (Section 13)."""

from __future__ import annotations

import re
from typing import Any

from shared.constants import REDACTED_PLACEHOLDER
from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    RedactionStatus,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.logging_config import redact_mapping, redact_text
from shared.schemas import ArtifactReference, VerificationResult
from shared.serialization import sha256_canonical, sha256_text

from agent_core.intelligence.context_budget import enforce_context_budget
from agent_core.intelligence.context_selector import (
    select_prioritized_artifacts,
    select_relevant_advisories,
    select_relevant_dependencies,
    select_relevant_excerpts,
)
from agent_core.intelligence.investigation_context import (
    AdvisoryContextItem,
    ContextAuditMetadata,
    DependencyMetadataItem,
    ExcludedContextItem,
    InvestigationContext,
    InvestigationInputBundle,
    SourceExcerpt,
    VerificationContextSummary,
)
from agent_core.llm.token_budget import TokenBudgetPolicy

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_MAX_EXCERPT_LINES = 80
_MAX_ADVISORY_SUMMARY_CHARS = 320


def _sanitize_context_text(text: str) -> tuple[str, int]:
    """Redact credentials, tokens, headers, and PII emails while keeping technical meaning."""
    redacted = redact_text(text)
    redactions = 1 if redacted != text else 0
    email_scrubbed, email_count = _EMAIL_RE.subn(REDACTED_PLACEHOLDER, redacted)
    return email_scrubbed, redactions + email_count


class InvestigationContextBuilder:
    """Executes all 10 stages of Section 13 context preparation cleanly and deterministically."""

    def __init__(self, *, budget_policy: TokenBudgetPolicy | None = None) -> None:
        self.budget_policy = budget_policy or TokenBudgetPolicy()

    def build(
        self,
        bundle: InvestigationInputBundle,
        *,
        has_tools: bool = False,
    ) -> InvestigationContext:
        finding = bundle.finding
        excluded: list[ExcludedContextItem] = []
        known_limitations: list[str] = []
        missing_info: list[str] = []
        redactions_total = 0

        # ------------------------------------------------------------------
        # Stage 1 & 2 — Collect & Validate identity, env, revision, provenance
        # ------------------------------------------------------------------
        target_env = finding.environment
        target_rev = finding.repository_revision

        valid_artifacts: list[ArtifactReference] = []
        for art in bundle.evidence_artifacts:
            if art.incident_id != finding.incident_id:
                excluded.append(
                    ExcludedContextItem(
                        item_id=art.artifact_id,
                        item_kind="artifact",
                        reason_code="INCIDENT_MISMATCH",
                        reason=(
                            f"Artifact belongs to incident {art.incident_id!r}, "
                            f"expected {finding.incident_id!r}."
                        ),
                    )
                )
                continue
            art_env = bundle.artifact_environments.get(art.artifact_id)
            if target_env and art_env and art_env != target_env:
                excluded.append(
                    ExcludedContextItem(
                        item_id=art.artifact_id,
                        item_kind="artifact",
                        reason_code="ENVIRONMENT_MISMATCH",
                        reason=(
                            f"Artifact environment {art_env!r} mismatches finding "
                            f"environment {target_env!r}."
                        ),
                    )
                )
                known_limitations.append(
                    f"Excluded artifact {art.artifact_id} due to environment mismatch."
                )
                continue
            if target_rev and art.source_revision and art.source_revision != target_rev:
                excluded.append(
                    ExcludedContextItem(
                        item_id=art.artifact_id,
                        item_kind="artifact",
                        reason_code="REVISION_MISMATCH",
                        reason=(
                            f"Artifact revision {art.source_revision!r} != {target_rev!r}."
                        ),
                    )
                )
                known_limitations.append(
                    f"Excluded artifact {art.artifact_id} due to source revision mismatch."
                )
                continue
            valid_artifacts.append(art)

        valid_verifications: list[VerificationResult] = []
        for ver in bundle.verification_results:
            if ver.incident_id != finding.incident_id:
                excluded.append(
                    ExcludedContextItem(
                        item_id=ver.verification_id,
                        item_kind="verification_result",
                        reason_code="INCIDENT_OR_FINDING_MISMATCH",
                        reason="VerificationResult incident_id mismatches target incident.",
                    )
                )
                continue
            ver_env = bundle.verification_environments.get(ver.verification_id)
            if target_env and ver_env and ver_env != target_env:
                excluded.append(
                    ExcludedContextItem(
                        item_id=ver.verification_id,
                        item_kind="verification_result",
                        reason_code="ENVIRONMENT_MISMATCH",
                        reason=(
                            f"Verification environment {ver_env!r} mismatches finding "
                            f"environment {target_env!r}."
                        ),
                    )
                )
                known_limitations.append(
                    f"Excluded verification {ver.verification_id} due to environment mismatch."
                )
                continue
            if target_rev and ver.tested_revision and ver.tested_revision != target_rev:
                excluded.append(
                    ExcludedContextItem(
                        item_id=ver.verification_id,
                        item_kind="verification_result",
                        reason_code="REVISION_MISMATCH",
                        reason=(
                            f"Verification revision {ver.tested_revision!r} != {target_rev!r}."
                        ),
                    )
                )
                known_limitations.append(
                    f"Excluded verification {ver.verification_id} due to source revision mismatch."
                )
                continue
            if ver.provenance not in {
                EvidenceProvenance.SECURITY_TEST_OUTPUT,
                EvidenceProvenance.ACTUAL_OBSERVED,
                EvidenceProvenance.REFERENCE_FIXTURE,
            }:
                excluded.append(
                    ExcludedContextItem(
                        item_id=ver.verification_id,
                        item_kind="verification_result",
                        reason_code="UNTRUSTED_PROVENANCE",
                        reason=f"Untrusted verification provenance {ver.provenance.value!r}.",
                    )
                )
                continue
            valid_verifications.append(ver)

        valid_excerpts: list[SourceExcerpt] = []
        for ex in bundle.source_excerpts:
            if not ex.authorized:
                excluded.append(
                    ExcludedContextItem(
                        item_id=ex.file_id,
                        item_kind="source_excerpt",
                        reason_code="UNAUTHORIZED_EXCERPT",
                        reason="Source excerpt not marked authorized for inclusion.",
                    )
                )
                continue
            if (
                bundle.authorized_source_paths is not None
                and ex.file_path not in bundle.authorized_source_paths
            ):
                excluded.append(
                    ExcludedContextItem(
                        item_id=ex.file_id,
                        item_kind="source_excerpt",
                        reason_code="PATH_NOT_AUTHORIZED",
                        reason=f"Path {ex.file_path!r} outside authorized source paths.",
                    )
                )
                continue
            if target_rev and ex.source_revision and ex.source_revision != target_rev:
                excluded.append(
                    ExcludedContextItem(
                        item_id=ex.file_id,
                        item_kind="source_excerpt",
                        reason_code="REVISION_MISMATCH",
                        reason=(
                            f"Source excerpt revision {ex.source_revision!r} != {target_rev!r}."
                        ),
                    )
                )
                known_limitations.append(
                    f"Excluded source excerpt {ex.file_id} due to revision mismatch."
                )
                continue
            valid_excerpts.append(ex)

        # Build verification summary preserving contradictory outcomes (never merged silently!)
        before_vers = [
            v for v in valid_verifications if v.phase == VerificationPhase.BEFORE_CONTAINMENT
        ]
        if not before_vers:
            before_vers = valid_verifications

        ver_summary = _build_verification_summary(
            before_vers,
            default_env=target_env,
            default_rev=target_rev,
            known_limitations=known_limitations,
        )

        # Cross-check artifact references against rejected IDs
        valid_art_ids = {a.artifact_id for a in valid_artifacts}
        if finding.status == FindingStatus.REPRODUCED and (
            ver_summary.reproduction_outcome != "reproduced"
        ):
            missing_info.append("consistent_reproduction_verification")

        if not valid_excerpts:
            missing_info.append("authorized_source_excerpt")
        if not valid_artifacts and not finding.evidence_ids:
            missing_info.append("supporting_evidence_artifacts")

        # ------------------------------------------------------------------
        # Stage 3 & 4 — Classify & Prioritize relevant evidence/context
        # ------------------------------------------------------------------
        selected_artifacts = select_prioritized_artifacts(valid_artifacts, finding=finding)
        selected_excerpts = select_relevant_excerpts(valid_excerpts, finding=finding)
        selected_deps = select_relevant_dependencies(bundle.dependencies, finding=finding)
        selected_advs = select_relevant_advisories(bundle.advisories, finding=finding)

        # ------------------------------------------------------------------
        # Stage 5 — Sanitize (secret & PII redaction)
        # ------------------------------------------------------------------
        sanitized_summaries: dict[str, str] = {}
        for art in selected_artifacts:
            raw_sum = bundle.evidence_summaries.get(art.artifact_id, "")
            if raw_sum:
                clean_sum, cnt = _sanitize_context_text(raw_sum)
                sanitized_summaries[art.artifact_id] = clean_sum
                redactions_total += cnt

        sanitized_excerpts: list[SourceExcerpt] = []
        for ex in selected_excerpts:
            clean_code, cnt = _sanitize_context_text(ex.code_excerpt)
            redactions_total += cnt
            sanitized_excerpts.append(
                ex.model_copy(
                    update={
                        "code_excerpt": clean_code,
                        "content_hash": sha256_text(clean_code),
                    }
                )
            )

        sanitized_advs: list[AdvisoryContextItem] = []
        for adv in selected_advs:
            clean_adv, cnt = _sanitize_context_text(adv.summary)
            redactions_total += cnt
            sanitized_advs.append(adv.model_copy(update={"summary": clean_adv}))

        clean_manifest = redact_mapping(bundle.application_manifest_summary)
        if clean_manifest != bundle.application_manifest_summary:
            redactions_total += 1

        clean_finding = finding
        if finding.observed_impact:
            clean_imp, cnt = _sanitize_context_text(finding.observed_impact)
            if cnt:
                redactions_total += cnt
                clean_finding = finding.model_copy(update={"observed_impact": clean_imp})

        # ------------------------------------------------------------------
        # Stage 6 — Deduplicate (never merging conflicting verifications)
        # ------------------------------------------------------------------
        seen_art_ids: set[str] = set()
        dedup_artifacts: list[ArtifactReference] = []
        for art in selected_artifacts:
            if art.artifact_id in seen_art_ids:
                continue
            seen_art_ids.add(art.artifact_id)
            dedup_artifacts.append(art)

        seen_ex_hashes: set[str] = set()
        dedup_excerpts: list[SourceExcerpt] = []
        for ex in sanitized_excerpts:
            sig = f"{ex.file_path}:{ex.content_hash}"
            if sig in seen_ex_hashes:
                continue
            seen_ex_hashes.add(sig)
            dedup_excerpts.append(ex)

        seen_adv_ids: set[str] = set()
        dedup_advisories: list[AdvisoryContextItem] = []
        for adv in sanitized_advs:
            if adv.advisory_id in seen_adv_ids:
                continue
            seen_adv_ids.add(adv.advisory_id)
            dedup_advisories.append(adv)

        seen_deps: set[str] = set()
        dedup_deps: list[DependencyMetadataItem] = []
        for dep in selected_deps:
            key = f"{dep.dependency_name}@{dep.installed_version}"
            if key in seen_deps:
                continue
            seen_deps.add(key)
            dedup_deps.append(dep)

        # ------------------------------------------------------------------
        # Stage 7 — Deterministic compression
        # ------------------------------------------------------------------
        compressed_excerpts: list[SourceExcerpt] = []
        truncation_reasons: list[str] = []
        for ex in dedup_excerpts:
            lines = ex.code_excerpt.splitlines()
            if len(lines) > _MAX_EXCERPT_LINES:
                compact_code = "\n".join(lines[:_MAX_EXCERPT_LINES]) + "\n# ...[BOUNDED]"
                truncation_reasons.append(f"line_bounded_excerpt({ex.file_id})")
                compressed_excerpts.append(ex.model_copy(update={"code_excerpt": compact_code}))
            else:
                compressed_excerpts.append(ex)

        compressed_advisories: list[AdvisoryContextItem] = []
        for adv in dedup_advisories:
            if len(adv.summary) > _MAX_ADVISORY_SUMMARY_CHARS:
                compact_sum = adv.summary[: _MAX_ADVISORY_SUMMARY_CHARS - 3] + "..."
                truncation_reasons.append(f"compacted_advisory({adv.advisory_id})")
                compressed_advisories.append(adv.model_copy(update={"summary": compact_sum}))
            else:
                compressed_advisories.append(adv)

        feature_names: list[str] = []
        if bundle.declared_features:
            feature_names = sorted({fs.feature_name for fs in bundle.declared_features})
        elif bundle.route_registry is not None:
            feature_names = sorted(set(bundle.route_registry.declared_features))

        provenances: list[EvidenceProvenance] = list(
            dict.fromkeys([clean_finding.provenance, *(a.provenance for a in dedup_artifacts)])
        )

        # ------------------------------------------------------------------
        # Stage 8, 9, 10 — Budget, Serialize & Hash + Audit
        # ------------------------------------------------------------------
        draft_ctx = InvestigationContext(
            incident_id=clean_finding.incident_id,
            finding=clean_finding,
            affected_route=clean_finding.affected_route,
            affected_component=clean_finding.affected_component,
            repository_revision=target_rev,
            environment=target_env,
            verification_summary=ver_summary,
            evidence_references=dedup_artifacts,
            evidence_summaries={
                k: v for k, v in sanitized_summaries.items() if k in valid_art_ids
            },
            bounded_source_excerpts=compressed_excerpts,
            dependency_metadata=dedup_deps,
            advisory_context=compressed_advisories,
            declared_feature_registry_summary=feature_names,
            application_manifest_summary=clean_manifest,
            known_limitations=list(dict.fromkeys(known_limitations)),
            missing_information=list(dict.fromkeys(missing_info)),
            excluded_items=excluded,
            data_provenance=provenances,
            has_deployment_evidence=bundle.has_deployment_evidence,
            has_containment_evidence=bundle.has_containment_evidence,
        )

        budgeted_ctx, pre_tok, post_tok, budget_truncations = enforce_context_budget(
            draft_ctx, policy=self.budget_policy, has_tools=has_tools
        )
        all_truncations = list(dict.fromkeys([*truncation_reasons, *budget_truncations]))
        ctx_hash = sha256_canonical(budgeted_ctx.to_prompt_payload())
        redaction_status = (
            RedactionStatus.REDACTED if redactions_total > 0 else RedactionStatus.NOT_REQUIRED
        )
        audit = ContextAuditMetadata(
            context_hash=ctx_hash,
            included_evidence_ids=sorted(budgeted_ctx.allowed_evidence_ids()),
            excluded_items=budgeted_ctx.excluded_items,
            redaction_status=redaction_status,
            redacted_fields_count=redactions_total,
            truncated=bool(all_truncations),
            truncation_reasons=all_truncations,
            estimated_tokens=post_tok,
            measured_tokens=None,
            token_count_source="estimated",
            pre_reduction_tokens=pre_tok,
            post_reduction_tokens=post_tok,
        )
        return budgeted_ctx.model_copy(update={"context_hash": ctx_hash, "audit": audit})


def _build_verification_summary(
    verifications: list[VerificationResult],
    *,
    default_env: str | None,
    default_rev: str | None,
    known_limitations: list[str],
) -> VerificationContextSummary:
    if not verifications:
        known_limitations.append("No trusted security verification test result was supplied.")
        return VerificationContextSummary(
            reproduction_outcome="not_run",
            environment=default_env,
            tested_revision=default_rev,
            known_limitations=["No security verification test executed."],
        )

    outcomes: list[str] = []
    artifact_ids: list[str] = []
    for v in verifications:
        artifact_ids.extend(v.artifact_ids)
        if v.execution_status == TestExecutionStatus.NOT_RUN:
            outcomes.append("not_run")
        elif v.execution_status == TestExecutionStatus.INFRASTRUCTURE_ERROR:
            outcomes.append("infrastructure_error")
        elif (
            v.vulnerability_reproduced is True
            and v.execution_status == TestExecutionStatus.TEST_PASSED
        ):
            outcomes.append("reproduced")
        elif v.vulnerability_reproduced is False:
            outcomes.append("not_confirmed")
        else:
            outcomes.append("inconclusive")

    distinct_outcomes = set(outcomes)
    conflicting = len(distinct_outcomes) > 1
    if conflicting:
        known_limitations.append(
            f"Conflicting verification outcomes observed across supplied tests: "
            f"{sorted(distinct_outcomes)}."
        )
        resolved_outcome: Any = "inconclusive"
    else:
        resolved_outcome = outcomes[0]

    latest = verifications[-1]
    ver_ts = (latest.completed_at or latest.started_at)
    return VerificationContextSummary(
        security_test_id=latest.test_id,
        test_run_id=latest.verification_id,
        reproduction_outcome=resolved_outcome,
        test_phase=latest.phase,
        environment=default_env,
        tested_revision=latest.tested_revision or default_rev,
        verification_timestamp=ver_ts.isoformat() if ver_ts is not None else None,
        artifact_references=list(dict.fromkeys(artifact_ids)),
        known_limitations=list(dict.fromkeys([*(latest.limitations or []), *known_limitations])),
        conflicting_outcomes=conflicting,
        observed_outcomes=outcomes,
    )
