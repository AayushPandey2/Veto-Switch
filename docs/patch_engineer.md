# Phase 07 — Evidence-Grounded AI Patch Engineer

## 1. Architecture Overview

`EvidenceGroundedPatchEngineer` (`remediation/patch_agent.py`) implements `PatchEngineerAgent` without executing candidate code, mutating mainline source, or bypassing isolated Phase 08 verification.

Pipeline:
1. **Target Distinction & Source Access** (`remediation/patching/source_access.py`): Explicitly distinguishes `stand_in` (`security/stand_in_app/app.py`, `sandbox_supported=True`) from `platform_demo_app` (`platform/demo_app/vulnerable_search_service.py`, `sandbox_supported=False`). Loads bounded, revision-bound `SourceSnapshot`s rejecting symlinks and traversal.
2. **AST Localization & Context Engineering** (`localize_vulnerability`, `build_patch_context`): Bounded Python AST inspection locates target functions (`search_v1`, `files_v1`, `search_documents`) and extracts redacted source excerpts.
3. **LLM Generation & Reference Fallback** (`remediation/patch_agent.py`): Routes `AITaskType.CANDIDATE_PATCH_GENERATION` through `LLMGateway` with `DataClassification.SENSITIVE_SOURCE`, versioned prompts (`remediation/prompts/patch_engineer/`), and bounded repair attempts. Falls back to revision-compatible `PatchOrigin.REFERENCE_FIXTURE` diffs only when target, category, and exact context match.
4. **Strict Diff Parsing, Applicability & Static Safety** (`remediation/patching/diff_validator.py`): Parses unified diffs strictly, derives `actual_touched_files` from diff headers, applies hunks in memory with exact context matching, inspects reconstructed ASTs for forbidden imports/calls and test gaming, and computes `MinimalityMetrics` and LF-normalized UTF-8 `candidate_content_hash`.
5. **Review Outputs & Orchestrator Integration** (`remediation/patching/review.py`, `agent_core/orchestrator.py`): Generates `TestPlan`, `ReviewerChecklist`, PR-ready Markdown summary, and dashboard JSON. `IncidentOrchestrator.execute_patch_generation` persists the `ArtifactType.PATCH_DIFF` artifact before emitting `PATCH_PROPOSED`, remaining in `PATCH_PENDING` until Phase 08 isolated testing.

## 2. Verification Commands

```bash
.venv/bin/mypy shared agent_core remediation
.venv/bin/python -m remediation.demos
.venv/bin/python -m remediation.evaluations.patch_evaluator
.venv/bin/pytest -v
```
