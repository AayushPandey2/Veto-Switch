"""Evidence-Grounded AI Patch Engineer implementing ``PatchEngineerAgent``.

Generates minimal, reviewable unified-diff candidates bound to an exact authorized
source snapshot and revision, with deterministic AST safety validation, bounded
LLM repair, and revision-compatible reference-fixture fallback.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from agent_core.context import Clock, PatchEngineerAgent, SystemClock
from agent_core.llm.gateway import LLMGateway
from shared.contracts import EvidenceRepository
from shared.enums import (
    AITaskType,
    ArtifactType,
    DataClassification,
    EvidenceProvenance,
    FindingStatus,
    PatchOrigin,
    PatchRejectionReason,
    PatchStatus,
    RedactionStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
)
from shared.exceptions import ContractValidationError, KillswitchError, PatchValidationError
from shared.identifiers import generate_artifact_id, generate_patch_id
from shared.schemas import (
    ArtifactReference,
    Finding,
    ModelMetadata,
    PatchProposal,
    VerificationResult,
)

from remediation.patching.diff_validator import (
    apply_diff_in_memory,
    compute_candidate_hash,
    compute_candidate_manifest_fingerprint,
    compute_minimality_metrics,
    normalize_diff_wrapper,
    parse_unified_diff,
    validate_patch_proposal,
    validate_static_safety,
)
from remediation.patching.models import (
    LLMGeneratedPatchCandidate,
    PatchGenerationContext,
    PatchGenerationOutcome,
    PatchLimitsConfig,
)
from remediation.patching.review import (
    build_pr_summary_markdown,
    build_reviewer_checklist,
    build_test_plan,
)
from remediation.patching.source_access import (
    STAND_IN_TARGET,
    build_patch_context,
    load_snapshot_from_files,
)

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts" / "patch_engineer"

_STAND_IN_SQLI_REFERENCE_DIFF = """--- a/app.py
+++ b/app.py
@@ -5,5 +5,3 @@
 def search_v1(q: str):
-    # DELIBERATELY VULNERABLE (demo only): user input concatenated into SQL.
-    sql = ("SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE '%"
-           + q + "%' ORDER BY title")
-    return db().execute(sql).fetchall()
+    sql = "SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE ? ORDER BY title"
+    return db().execute(sql, (f"%{q}%",)).fetchall()
"""

_STAND_IN_TRAVERSAL_REFERENCE_DIFF = """--- a/app.py
+++ b/app.py
@@ -11,5 +11,7 @@
 def files_v1(name: str):
-    # DELIBERATELY VULNERABLE (demo only): no normalization or root check.
-    path = os.path.join(DOC_ROOT, name)
+    root = os.path.realpath(DOC_ROOT)
+    path = os.path.realpath(os.path.join(root, name))
+    if not name or os.path.commonpath([root, path]) != root or not os.path.isfile(path):
+        raise ValueError("path outside document root")
     with open(path, encoding="utf-8") as f:
         return f.read()
"""

_PLATFORM_SQLI_REFERENCE_DIFF = """--- a/vulnerable_search_service.py
+++ b/vulnerable_search_service.py
@@ -1,3 +1,3 @@
 def search_documents(conn, q: str):
-    sql = f"SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE '%{q}%'"
-    return conn.execute(sql).fetchall()
+    sql = "SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE ?"
+    return conn.execute(sql, (f"%{q}%",)).fetchall()
"""


def _load_prompt_file(name: str, default_text: str) -> str:
    p = _PROMPTS_DIR / name
    return p.read_text(encoding="utf-8") if p.exists() else default_text


def _select_reference_fallback(
    context: PatchGenerationContext,
) -> tuple[str, str, list[str], list[str]] | None:
    """Return compatible reference diff ONLY when target, category, and context match."""
    target_id = context.target_descriptor.target_id
    cat = context.finding.category
    if target_id == "stand_in" and cat == VulnerabilityCategory.SQL_INJECTION:
        return (
            _STAND_IN_SQLI_REFERENCE_DIFF,
            "Reference fixture: parameterize SQL query in search_v1 using '?' placeholder.",
            ["Parameterized SQL prevents injection while preserving public document search."],
            ["Requires Phase 08 sqli_search, functional_search, and negative_inputs_search."],
        )
    if target_id == "stand_in" and cat == VulnerabilityCategory.PATH_TRAVERSAL:
        return (
            _STAND_IN_TRAVERSAL_REFERENCE_DIFF,
            "Reference fixture: canonicalize path with os.path.realpath and enforce commonpath.",
            ["Blocks directory traversal outside DOC_ROOT with ValueError."],
            ["Requires Phase 08 traversal_files, functional_files, and negative_inputs_files."],
        )
    if target_id == "platform_demo_app" and cat == VulnerabilityCategory.SQL_INJECTION:
        return (
            _PLATFORM_SQLI_REFERENCE_DIFF,
            "Reference fixture: parameterize SQL query in platform vulnerable_search_service.py.",
            ["Parameterized SQL prevents injection on platform demo search service."],
            ["Platform target is not registered in the isolated security sandbox yet."],
        )
    return None


class EvidenceGroundedPatchEngineer(PatchEngineerAgent):
    """Production-intended AI Patch Engineer implementing ``PatchEngineerAgent``."""

    def __init__(
        self,
        *,
        llm_gateway: LLMGateway | None = None,
        evidence_repository: EvidenceRepository | None = None,
        clock: Clock | None = None,
        limits: PatchLimitsConfig | None = None,
        default_target_files: dict[str, str] | None = None,
        fixture_mode: bool = False,
    ) -> None:
        self._gateway = llm_gateway
        self._evidence_repo = evidence_repository
        self._clock: Clock = clock or SystemClock()
        self._limits = limits or PatchLimitsConfig()
        self._default_target_files = default_target_files
        self._fixture_mode = fixture_mode

    def _check_eligibility(
        self, context: PatchGenerationContext, *, require_contained: bool = True
    ) -> list[PatchRejectionReason]:
        reasons: list[PatchRejectionReason] = []
        finding = context.finding
        if finding.incident_id != context.incident_id:
            reasons.append(PatchRejectionReason.MANUAL_REVIEW_REQUIRED)
        if finding.status != FindingStatus.REPRODUCED:
            reasons.append(PatchRejectionReason.FINDING_NOT_REPRODUCED)
        if not finding.evidence_ids:
            reasons.append(PatchRejectionReason.MISSING_REPRODUCTION_EVIDENCE)
        if require_contained and context.containment_verification is not None:
            cv = context.containment_verification
            if cv.phase == VerificationPhase.AFTER_CONTAINMENT and (
                cv.execution_status != TestExecutionStatus.TEST_PASSED or cv.passed is not True
            ):
                reasons.append(PatchRejectionReason.CONTAINMENT_NOT_VERIFIED)
        if finding.category not in set(context.target_descriptor.supported_categories):
            reasons.append(PatchRejectionReason.UNSUPPORTED_VULNERABILITY_CATEGORY)
        if (
            finding.repository_revision
            and finding.repository_revision != context.source_snapshot.source_revision
        ):
            reasons.append(PatchRejectionReason.SOURCE_REVISION_MISMATCH)
        if context.localization.outcome in {
            "source_unavailable",
            "source_revision_mismatch",
            "multiple_candidate_locations",
        }:
            reasons.append(PatchRejectionReason.AMBIGUOUS_SOURCE_LOCATION)
        return sorted(set(reasons), key=lambda r: r.value)

    def _validate_candidate_diff(
        self,
        raw_diff: str,
        context: PatchGenerationContext,
    ) -> tuple[str, list[str], dict[str, str], list[PatchRejectionReason]]:
        try:
            normalized_diff = normalize_diff_wrapper(raw_diff)
            parsed = parse_unified_diff(normalized_diff, limits=self._limits)
            reconstructed = apply_diff_in_memory(context.source_snapshot, parsed)
        except PatchValidationError as exc:
            raw_code = exc.context.get("reason", PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value)
            return "", [], {}, [PatchRejectionReason(raw_code)]

        safety_reasons = validate_static_safety(
            reconstructed,
            parsed,
            allowed_files=context.target_descriptor.allowed_files,
        )
        if safety_reasons:
            return normalized_diff, parsed.actual_touched_files, reconstructed, safety_reasons
        return normalized_diff, parsed.actual_touched_files, reconstructed, []

    async def generate_candidate(
        self,
        context: PatchGenerationContext,
        *,
        require_contained: bool = True,
        allow_fixture_fallback: bool = True,
    ) -> PatchGenerationOutcome:
        """Run end-to-end bounded patch generation, static validation, and artifact storage."""
        elig_reasons = self._check_eligibility(context, require_contained=require_contained)
        test_plan = build_test_plan(context.finding, context.target_descriptor)
        if elig_reasons:
            return PatchGenerationOutcome(
                accepted=False,
                test_plan=test_plan,
                rejection_reasons=elig_reasons,
                limitations=[
                    f"Remediation eligibility gate rejected candidate generation: "
                    f"{[r.value for r in elig_reasons]}."
                ],
                sandbox_ready=False,
                manual_review_required=True,
            )

        sys_prompt = _load_prompt_file(
            "system.md", "Generate a minimal, safe unified diff for the verified finding."
        )
        gen_tpl = _load_prompt_file("generation.md", "Target: {{target_id}}\n{{source_excerpts}}")
        repair_tpl = _load_prompt_file(
            "repair_output.md", "Validation errors: {{validation_errors}}"
        )

        excerpts_text = "\n\n".join(
            f"### {ex.file_path} (lines {ex.start_line}-{ex.end_line})\n"
            f"```python\n{ex.content}\n```"
            for ex in context.relevant_source_excerpts
        )
        user_msg = (
            gen_tpl.replace("{{incident_id}}", context.incident_id)
            .replace("{{finding_id}}", context.finding.finding_id)
            .replace("{{category}}", context.finding.category.value)
            .replace("{{affected_route}}", str(context.finding.affected_route or "unknown"))
            .replace("{{affected_component}}", context.affected_component)
            .replace("{{target_id}}", context.target_descriptor.target_id)
            .replace("{{source_revision}}", context.source_snapshot.source_revision)
            .replace("{{allowed_files}}", str(context.target_descriptor.allowed_files))
            .replace("{{required_test_ids}}", str(test_plan.mandatory_registered_tests))
            .replace("{{remediation_constraints}}", "\n".join(context.remediation_constraints))
            .replace("{{source_excerpts}}", excerpts_text)
        )

        candidate_diff = ""
        rationale = ""
        expected_changes: list[str] = []
        regressions: list[str] = []
        assumptions: list[str] = []
        suggested_tests: list[str] = []
        model_meta: ModelMetadata | None = None
        patch_origin: PatchOrigin = PatchOrigin.LLM_CANDIDATE
        last_reasons: list[PatchRejectionReason] = []
        limitations: list[str] = list(test_plan.limitations)

        if self._gateway is not None:
            attempts = 1 + self._limits.maximum_repair_attempts
            current_user_msg = user_msg
            for _attempt in range(attempts):
                try:
                    gw_res = await self._gateway.generate_structured(
                        AITaskType.CANDIDATE_PATCH_GENERATION,
                        {
                            "incident_id": context.incident_id,
                            "finding_id": context.finding.finding_id,
                            "allowed_files": context.target_descriptor.allowed_files,
                            "source_revision": context.source_snapshot.source_revision,
                        },
                        LLMGeneratedPatchCandidate,
                        incident_id=context.incident_id,
                        authorized_source_paths=set(context.target_descriptor.allowed_files),
                        data_classification=DataClassification.SENSITIVE_SOURCE,
                        max_output_tokens=self._limits.maximum_output_tokens,
                        timeout_seconds=self._limits.provider_timeout_seconds,
                        system_prompt_override=sys_prompt,
                        user_message_override=current_user_msg,
                    )
                except KillswitchError as exc:
                    last_reasons = [PatchRejectionReason.MODEL_PROVIDER_UNAVAILABLE]
                    limitations.append(f"LLM generation failed: {exc.message}")
                    break

                llm_cand = gw_res.parsed
                norm_diff, _touched, _recon, val_reasons = self._validate_candidate_diff(
                    llm_cand.unified_diff, context
                )
                if not val_reasons:
                    candidate_diff = norm_diff
                    rationale = llm_cand.technical_rationale
                    expected_changes = list(llm_cand.expected_behavior_changes)
                    regressions = list(llm_cand.potential_regressions)
                    assumptions = list(llm_cand.assumptions)
                    suggested_tests = list(llm_cand.suggested_test_ids)
                    model_meta = gw_res.model_metadata
                    patch_origin = (
                        PatchOrigin.REFERENCE_FIXTURE
                        if gw_res.model_metadata.provider == "offline_fixture"
                        else PatchOrigin.LLM_CANDIDATE
                    )
                    last_reasons = []
                    break

                last_reasons = val_reasons
                current_user_msg = (
                    repair_tpl.replace(
                        "{{validation_errors}}", ", ".join(r.value for r in val_reasons)
                    ).replace("{{allowed_files}}", str(context.target_descriptor.allowed_files))
                )
        else:
            last_reasons = [PatchRejectionReason.MODEL_PROVIDER_UNAVAILABLE]

        if not candidate_diff and allow_fixture_fallback:
            fb = _select_reference_fallback(context)
            if fb is not None:
                fb_diff, fb_rat, fb_changes, fb_reg = fb
                norm_diff, _touched, _recon, val_reasons = self._validate_candidate_diff(
                    fb_diff, context
                )
                if not val_reasons:
                    candidate_diff = norm_diff
                    rationale = fb_rat
                    expected_changes = fb_changes
                    regressions = fb_reg
                    assumptions = [
                        "Fallback reference fixture selected; not newly authored by LLM."
                    ]
                    patch_origin = PatchOrigin.REFERENCE_FIXTURE
                    model_meta = None
                    last_reasons = []
                else:
                    last_reasons = val_reasons
            else:
                last_reasons.append(PatchRejectionReason.FIXTURE_FALLBACK_UNAVAILABLE)

        if not candidate_diff:
            return PatchGenerationOutcome(
                accepted=False,
                test_plan=test_plan,
                rejection_reasons=sorted(set(last_reasons), key=lambda r: r.value),
                limitations=limitations,
                sandbox_ready=False,
                manual_review_required=True,
            )

        parsed = parse_unified_diff(candidate_diff, limits=self._limits)
        reconstructed = apply_diff_in_memory(context.source_snapshot, parsed)
        minimality = compute_minimality_metrics(parsed, reconstructed)
        final_test_plan = build_test_plan(
            context.finding,
            context.target_descriptor,
            suggested_tests=suggested_tests,
        )
        content_hash = compute_candidate_hash(candidate_diff)
        patch_id = generate_patch_id()
        artifact_id = generate_artifact_id()

        required_tests = list(final_test_plan.mandatory_registered_tests) or [
            "manual_security_and_functional_review"
        ]
        proposal = PatchProposal(
            patch_id=patch_id,
            incident_id=context.incident_id,
            finding_id=context.finding.finding_id,
            source_revision=context.source_snapshot.source_revision,
            candidate_artifact_id=artifact_id,
            candidate_content_hash=content_hash,
            unified_diff=candidate_diff,
            allowed_files=list(context.target_descriptor.allowed_files),
            touched_files=list(parsed.actual_touched_files),
            technical_rationale=rationale,
            expected_behavior_changes=expected_changes,
            required_tests=required_tests,
            potential_regressions=regressions,
            assumptions=assumptions,
            patch_origin=patch_origin,
            status=PatchStatus.PATCH_PROPOSED,
            model_metadata=model_meta,
            review_required=True,
            created_at=self._clock.now(),
        )
        validate_patch_proposal(proposal, context, limits=self._limits)

        art_ref = ArtifactReference(
            artifact_id=artifact_id,
            incident_id=context.incident_id,
            artifact_type=ArtifactType.PATCH_DIFF,
            content_hash=content_hash,
            storage_ref=f"patches/{context.incident_id}/{patch_id}.diff",
            created_at=self._clock.now(),
            producer="remediation_patch_engineer",
            provenance=(
                EvidenceProvenance.REFERENCE_FIXTURE
                if patch_origin == PatchOrigin.REFERENCE_FIXTURE
                else EvidenceProvenance.LLM_INTERPRETATION
            ),
            content_type="text/x-diff",
            size_bytes=len(candidate_diff.encode("utf-8")),
            source_revision=context.source_snapshot.source_revision,
            redaction_status=RedactionStatus.REDACTED,
        )
        if self._evidence_repo is not None:
            await self._evidence_repo.store_artifact(art_ref, candidate_diff.encode("utf-8"))

        manifest_fp = compute_candidate_manifest_fingerprint(
            proposal,
            target_id=context.target_descriptor.target_id,
            snapshot_fingerprint=context.source_snapshot.snapshot_fingerprint,
        )
        checklist = build_reviewer_checklist(
            target=context.target_descriptor,
            test_plan=final_test_plan,
        )
        pr_md = build_pr_summary_markdown(
            finding=context.finding,
            target=context.target_descriptor,
            test_plan=final_test_plan,
            checklist=checklist,
            unified_diff=candidate_diff,
            technical_rationale=rationale,
            touched_files=parsed.actual_touched_files,
            candidate_content_hash=content_hash,
            patch_origin=patch_origin.value,
            expected_behavior_changes=expected_changes,
            potential_regressions=regressions,
            limitations=limitations,
        )

        return PatchGenerationOutcome(
            accepted=True,
            proposal=proposal,
            artifact_reference=art_ref,
            candidate_manifest_fingerprint=manifest_fp,
            test_plan=final_test_plan,
            checklist=checklist,
            pr_summary_markdown=pr_md,
            minimality=minimality,
            rejection_reasons=[],
            limitations=limitations,
            sandbox_ready=context.target_descriptor.sandbox_supported,
            manual_review_required=True,
        )

    async def propose_patch(
        self,
        finding: Finding,
        containment_verification: VerificationResult,
    ) -> PatchProposal:
        """``PatchEngineerAgent`` protocol entry point returning validated ``PatchProposal``."""
        if not self._default_target_files:
            raise ContractValidationError(
                "Authorized source files are required for PatchEngineerAgent.propose_patch."
            )
        target = STAND_IN_TARGET.model_copy(
            update={
                "source_revision": (
                    finding.repository_revision or STAND_IN_TARGET.source_revision
                ),
            }
        )
        snapshot = load_snapshot_from_files(
            target=target,
            files=self._default_target_files,
            limits=self._limits,
        )
        ctx = build_patch_context(
            finding=finding,
            target_descriptor=target,
            snapshot=snapshot,
            containment_verification=containment_verification,
            fixture_mode=self._fixture_mode,
            evaluation_timestamp=self._clock.now(),
            limits=self._limits,
        )
        outcome = await self.generate_candidate(ctx)
        if not outcome.accepted or outcome.proposal is None:
            raise ContractValidationError(
                "Patch generation failed deterministic validation.",
                context={"reasons": [r.value for r in outcome.rejection_reasons]},
            )
        return outcome.proposal

    async def propose_patch_for_files(
        self,
        finding: Finding,
        allowed_files: Sequence[str],
        revision: str,
        *,
        source_files: dict[str, str],
    ) -> dict[str, Any]:
        """Roadmap-compatible convenience interface returning serialized patch summary."""
        target = STAND_IN_TARGET.model_copy(
            update={"allowed_files": list(allowed_files), "source_revision": revision}
        )
        snapshot = load_snapshot_from_files(target=target, files=source_files, limits=self._limits)
        ctx = build_patch_context(
            finding=finding,
            target_descriptor=target,
            snapshot=snapshot,
            fixture_mode=self._fixture_mode,
            evaluation_timestamp=self._clock.now(),
            limits=self._limits,
        )
        outcome = await self.generate_candidate(ctx, require_contained=False)
        return outcome.model_dump(mode="json")
