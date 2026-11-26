# Killswitch X — Context Engineering & Token Budgeting

## 1. 10-Stage Context Pipeline (`InvestigationContextBuilder`)
1. **Collect**: Gather normalized `Finding`, `VerificationResult` records, `ArtifactReference` items, authorized `SourceExcerpt` items, dependencies, advisories, and optional feature/manifest metadata.
2. **Validate**: Exclude foreign `incident_id` artifacts, environment mismatches, source-revision mismatches, untrusted provenance verifications, and unauthorized file paths into explicit `ExcludedContextItem` records.
3. **Classify**: Classify artifacts by importance (`MANDATORY_EVIDENCE`, `RELEVANT_TECHNICAL`, `OPTIONAL_EXPLANATORY`, etc.).
4. **Select**: Prioritize reproduction logs/artifacts, matching source excerpts, and matching advisories deterministically above tangential files.
5. **Sanitize**: Scrub credentials, Bearer/JWT tokens, API keys, and email addresses via `shared.logging_config.redact_text` and `_EMAIL_RE`, recording `RedactionStatus`.
6. **Deduplicate**: Deduplicate identical artifacts, duplicate source excerpt hashes, and repeated advisories **without** merging conflicting verification outcomes (`conflicting_outcomes=True`).
7. **Compress**: Deterministically trim oversized line windows and advisory prose while preserving artifact IDs and conflict notes.
8. **Budget**: Enforce `TokenBudgetPolicy` headroom reservations via `enforce_context_budget`:
   - Drop optional manifest metadata -> compact feature registry summary -> trim verbose evidence summaries -> drop secondary source excerpts -> truncate long primary excerpts -> compact advisories -> fail explicitly with `TOKEN_BUDGET_EXCEEDED` if mandatory evidence still cannot fit.
9. **Serialize**: Emit deterministic JSON payload via `InvestigationContext.to_prompt_payload()`.
10. **Hash & Record**: Compute SHA-256 `context_hash` (`sha256_canonical`) and full `ContextAuditMetadata` tracking pre/post token counts and truncation reasons.

## 2. Token Accounting Honesty & Known Limitations
- `TokenCountResult` explicitly separates provider-measured counts (`source="measured"`) from deterministic character/structural estimates (`source="estimated"`).
- Pre-budgeting relies on character-based estimation when provider `count_tokens` is unavailable offline; latency/token savings reported reflect measured reduction tokens across truncated fixtures rather than extrapolated production averages.
