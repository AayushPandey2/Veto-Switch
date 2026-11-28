# ADR-006: Evidence-First Incident Management

## Context
During incident response, unverified scanner alerts, LLM hypotheses, and simulated fixtures can easily be confused with verified facts unless provenance and integrity are enforced at the contract level.

## Decision
Tag findings, feature observations, receipts, verification outcomes, telemetry, and artifacts with explicit `EvidenceProvenance` values, require `evidence_ids` for reproduced findings and containment proposals, and enforce SHA-256 digests on `ArtifactReference`.

## Alternatives
1. Storing untyped metadata dictionaries without provenance classification.
2. Allowing `status="reproduced"` or `completeness="complete"` without evidence references.

## Rationale
Explicit provenance and fail-closed evidence requirements ensure exported `EvidenceReport` bundles clearly separate observed facts, AI interpretations, and synthetic fixtures.

## Consequences
- Missing evidence forces hold/unverified states rather than optimistic progression.
- `OperationReceipt` explicitly rejects `EvidenceProvenance.LLM_INTERPRETATION`.

## Known Limitations
Structural ID validation in `shared/` must be paired with `EvidenceRepository.artifact_exists` in `platform/` to guarantee storage-level existence.
