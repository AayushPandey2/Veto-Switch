# Phase 08 Isolated Patch Verification Evaluation Report

- **Total Cases:** 15
- **Passed Cases:** 15
- **Unsafe False Passes:** 0
- **All Passed:** True

| Case ID | Passed | Expected Accepted | Actual Accepted | Status | Reasons |
| --- | --- | --- | --- | --- | --- |
| `pv_01_full_pass` | `True` | `True` | `True` | `test_passed` | `VERIFIED_READY_FOR_DEPLOYMENT` |
| `pv_02_security_fail` | `True` | `False` | `False` | `test_failed` | `SECURITY_REGRESSION_FAILED` |
| `pv_03_functional_fail` | `True` | `False` | `False` | `test_failed` | `FUNCTIONAL_REGRESSION_FAILED` |
| `pv_04_smoke_fail` | `True` | `False` | `False` | `test_failed` | `SMOKE_TEST_FAILED` |
| `pv_05_missing_smoke_plan` | `True` | `False` | `False` | `not_run` | `MISSING_SMOKE_TESTS` |
| `pv_06_runner_omits_test` | `True` | `False` | `False` | `test_failed` | `MISSING_SMOKE_TESTS` |
| `pv_07_base_revision_mismatch` | `True` | `False` | `False` | `test_failed` | `BASE_REVISION_MISMATCH` |
| `pv_08_patched_revision_mismatch` | `True` | `False` | `False` | `test_failed` | `PATCHED_REVISION_MISMATCH, RUNTIME_REVISION_MISMATCH` |
| `pv_09_runtime_revision_mismatch` | `True` | `False` | `False` | `test_failed` | `RUNTIME_REVISION_MISMATCH` |
| `pv_10_runtime_revision_missing` | `True` | `False` | `False` | `test_failed` | `RUNTIME_REVISION_MISSING` |
| `pv_11_candidate_hash_mismatch` | `True` | `False` | `False` | `not_run` | `CANDIDATE_HASH_MISMATCH` |
| `pv_12_unsupported_target` | `True` | `False` | `False` | `not_run` | `UNSUPPORTED_SOURCE_TARGET` |
| `pv_13_timeout_outcome_unknown` | `True` | `False` | `False` | `infrastructure_error` | `MISSING_SECURITY_TESTS, MISSING_FUNCTIONAL_TESTS, MISSING_SMOKE_TESTS, RUNTIME_REVISION_MISSING, INSUFFICIENT_ISOLATION, RUNNER_INFRASTRUCTURE_ERROR, PARTIAL_RESULTS_REJECTED` |
| `pv_14_insufficient_isolation` | `True` | `False` | `False` | `infrastructure_error` | `INSUFFICIENT_ISOLATION` |
| `pv_15_artifact_corrupted` | `True` | `False` | `False` | `infrastructure_error` | `EVIDENCE_PROVENANCE_UNTRUSTED` |
