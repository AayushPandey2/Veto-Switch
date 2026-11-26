# ADR-007: Isolated Patch Verification

## Context
Candidate source patches drafted by AI or retrieved from reference fixtures may contain syntax errors, functional regressions, incomplete fixes, or unsafe file modifications outside the target module.

## Decision
Constrain `PatchProposal` to safe relative POSIX paths within an explicit `allowed_files` list, submit candidate patches strictly through `PatchTestRunner` (with zero shell execution APIs), and validate `PatchTestResult` revision consistency (`expected_source_revision == tested_source_revision`) and non-overridable functional test results.

## Alternatives
1. Allowing `remediation` to invoke local `subprocess` / `pytest` directly in the main API process.
2. Treating security regression passes as sufficient even when functional tests fail.

## Rationale
Isolating candidate patch execution prevents untrusted code from compromising the orchestrator host and guarantees `is_trusted_pass` fails closed on revision mismatches or functional failures.

## Consequences
- `PatchTestResult` distinguishes `test_passed`, `test_failed`, `infrastructure_error`, and `not_run`.
- Future `security/` implementation must run patches in an isolated sandboxed runner.

## Known Limitations
Isolated test coverage is bounded by `PatchProposal.required_tests` and the isolated environment's fidelity.
