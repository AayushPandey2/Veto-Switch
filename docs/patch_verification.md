# Phase 08: Isolated Patch Verification & Regression Intelligence

## Overview

Phase 08 (`remediation/patch_tests.py`, `remediation/verification/`, `remediation/adapters/`) implements deterministic isolated verification for candidate patches produced by Phase 07. It executes **zero LLM calls** and **never runs untrusted candidate code on the host**.

## Key Guarantees

1. **Authorized Target Compatibility:** Only `stand_in` (`app.py`) supports isolated patch verification. `platform_demo_app` returns `not_run` (`UNSUPPORTED_SOURCE_TARGET`) rather than silently substituting `stand_in`.
2. **Independent Candidate Integrity:** Recomputes `candidate_content_hash`, verifies artifact bytes if supplied, and re-validates diff structure via `remediation.patching.diff_validator`.
3. **Mandatory Test-Plan Completeness:** Requires security regression, functional regression, negative-input, and unrelated smoke tests. Missing mandatory categories or omitted test outcomes block acceptance.
4. **5-Point Revision Identity:** Checks `base_source_revision`, `candidate_content_hash`, `expected_patched_revision`, `runner_computed_patched_revision`, and `runtime_observed_revision`. Missing runtime revision never counts as a match.
5. **Isolation & Evidence Policy:** Rejects `host` execution mode, non-ephemeral or network-enabled sandboxes, missing artifacts, untrusted provenance, and timeouts (`RUNNER_TIMEOUT_OUTCOME_UNKNOWN`).
6. **Separation of Concerns:** Accepted verification emits `RecoveryHandoff` with `candidate_tested=True`, `ready_for_deployment_verification=True`, `deployment_verified=False`, and `rollout_authorized=False`.

## Security Runner Integration

`SecurityServicePatchRunner` (`remediation/adapters/security_runner.py`) integrates with `security.service` (`POST /patches`, `POST /patch-tests`, `GET /health`, `GET /registry`, `GET /targets`, `GET /patches/base-revision`, `GET /artifacts/{incident_id}`) using `httpx.AsyncClient` with `X-KSX-Token` (`KSX_SECURITY_SERVICE_TOKEN`), `follow_redirects=False`, and bounded response sizes.

`FixturePatchTestRunner` (`remediation/adapters/fixture_runner.py`) provides explicit offline simulation across 15 scenarios.

## Running Offline Demos & Evaluation

```bash
python -m remediation.verification_demos
python -m remediation.evaluations.patch_verification_evaluator
```
