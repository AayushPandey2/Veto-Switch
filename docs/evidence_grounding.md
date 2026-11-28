# Killswitch X — Evidence Grounding & Uncertainty Model

## 1. Claim Classification & Grounding Checks
Claims in `InvestigationSummary` separate:
- `grounded_facts` (`ClaimCategory.OBSERVED`): Must reference >= 1 supplied, incident-scoped, env/revision-consistent `evidence_id`.
- `technical_interpretations` (`ClaimCategory.INFERRED`): Link to evidence/source excerpts and always flag `semantic_review_required=True` in `GroundingValidationReport` because structural reference validity never proves semantic correctness.
- `potential_impacts` (`PotentialImpact`): Explicit `verified` boolean (cannot be `True` unless finding and verification confirm reproduction).
- `assumptions`, `uncertainties`, and `missing_evidence`.

## 2. Deterministic Validation Rules (`claim_validator.py`, `evidence_grounding.py`)
Mechanical validation verifies and rejects:
- Nonexistent or excluded (wrong incident / wrong environment / wrong revision) `evidence_ids` or `source_excerpt_ids`.
- Observed claims lacking supporting `evidence_ids`.
- Reproduction or test-pass claims when verification outcome is `not_run`, `not_confirmed`, `infrastructure_error`, or conflicting, or when `finding.status == "suspected"`.
- Dependency CVE exploitation claims when only an advisory match exists without confirmed reproduction.
- Deployment/containment/recovery claims when deployment and containment evidence flags are absent.
- Single-route findings overgeneralizing to "all routes" or "entire database compromised".
- Hallucinated CVE identifiers (`CVE-YYYY-NNNN`) or unverified source file paths absent from supplied context.

## 3. Limitations & Human Review
Deterministic checks CANNOT guarantee universal truth of open-ended technical prose. Therefore `semantic_review_required` remains `True` whenever inferred interpretations exist, and `requires_manual_review` activates automatically for `other` categories, conflicting tests, excluded mismatched evidence, or failed grounding.
