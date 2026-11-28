# Killswitch X: security lane (`security/`)

This lane runs the controlled security tests: reproduce a planted bug, prove containment after a flag flip, and check a candidate patch. Every claim comes with an evidence artifact. Tests only run against **owned, allowlisted local targets** with **synthetic data**.

## Setup

```bash
uv sync --extra dev                           # creates .venv from pyproject.toml / uv.lock
.venv/Scripts/python.exe -m pytest            # 68 tests; the Docker test skips without a daemon
.venv/Scripts/python.exe -m pytest -m network # optional: checks the advisory fixture against live OSV
```

## Quick demo (CLI)

```bash
python -m security serve-target                      # stand-in target on 127.0.0.1:5001 (seeded, nonce 0000demo)
python -m security verify sqli_search --phase before # -> exploit_reproduced
python -m security flags search_v1=off               # simulates the approved Flagsmith change
python -m security verify sqli_search --phase after_containment   # -> contained (+ smoke results)
python -m security scan                              # fixture SARIF -> findings; reproduced ones carry evidence IDs
python -m security patch-test security/fixtures/patches/sqli_fix.diff --tests sqli_search,functional_search,negative_inputs_search,smoke_status
python -m security cve                               # dependency advisory matches (always "suspected")
python -m security cve --refresh GHSA-2g68-c3qc-8985 # diff the saved advisory against live OSV
python -m security artifacts inc-demo                # manifest + integrity re-hash
```

`patch-test` uses Docker by default. On a dev machine without Docker, set `KSX_ALLOW_LOCAL_SANDBOX=1` (see Limitations).

## Service for other lanes

```bash
uvicorn security.service:app --host 127.0.0.1 --port 8100   # OpenAPI at /docs
```

| Endpoint | Purpose |
|---|---|
| `POST /verify` `{incident_id,test_id,target_id,phase,revision?,expected_flags?}` | Phase verification. Returns `result` plus `events` (`verification_pass` / `verification_fail` / `verification_error`). |
| `POST /scan` `{target_id}` | Normalized findings plus `finding_reproduced` / `finding_suspected` events. |
| `GET /patches/base-revision` | Revision a patch must be written against, and the patch file allowlist. |
| `POST /patches` 🔒 | Submit a candidate diff (validated at submission time). |
| `POST /patch-tests` 🔒 `{patch_id,revision,test_ids}` | Run the patch in the sandbox. `status` is one of `test_passed`, `test_failed`, `infrastructure_error`, `not_run`. |
| `POST /cve/enrich` | Match a package and version against a saved advisory. |
| `GET /artifacts/{incident}` and `/{evidence_id}` | Evidence manifest, integrity check and artifact bodies. |

🔒 = requires the `X-KSX-Token` header to equal `KSX_SECURITY_SERVICE_TOKEN`. If the token is unset or still the placeholder, these endpoints refuse every request.

Python interfaces from the brief: `scanner.scan_demo`, `exploit_verifier.verify_vulnerability`, `exploit_verifier.verify_containment`, `sandbox.run_patch_tests`, `cve_matcher.enrich_dependency_finding`. There is also `exploit_verifier.verify_patch_target`.

## Phase semantics

`passed` on a `VerificationResult` means **the phase-specific assertion held**. `outcome` says exactly what happened.

| Phase | `passed=true` means | Possible outcomes |
|---|---|---|
| `before` | The vulnerability **reproduced** on the baseline (this is the expected result for a real finding) | `exploit_reproduced`, `exploit_not_reproduced` |
| `after_containment` | The exploit was blocked on the primary route **and every declared alias**, the app **itself reports** the expected flag state, and a benign request took the safe fallback without leaking data | `contained`, `contained_smoke_failed` (still passed, but containment was too broad), `containment_failed`, `flag_mismatch` |
| `after_patch` | The exploit was blocked **and** the functional, negative-input and smoke tests passed on the patched revision | `patch_verified`, `patch_failed` |
| any | — | `revision_mismatch`, `infrastructure_error`, `not_run`. All of these have `passed=false`, and none ever counts as contained. |

A successful flag write proves nothing. `flag_mismatch` covers the case where the exploit is blocked but the app does not report the expected flag state, for example because of SDK cache lag or a wrong environment. Containment is not attributed in that case.

## Oracles and fixtures

- **SQLi (`sqli_search`)**: the seeded private rows have titles starting `KSX-CANARY-PRIVATE-<nonce>`. If one shows up in `/search`, the boundary was crossed. A boolean-difference check (ported from ExhibitA) is recorded as corroboration only.
- **Traversal (`traversal_files`)**: a harmless sentinel file sits one level above the document root. If its content shows up in `/files`, the root was escaped. Only the sentinel is ever requested.
- When the sandbox launches a target itself, it uses a random nonce, so a match can only come from that run's fixture. External targets are seeded with `default_nonce`, and the oracles match on the prefix.
- `fixtures/seed_spec.json`: all fake data. `fixtures/scanner/demo_scan.sarif.json`: saved scan output (it contains a deliberate duplicate to test dedupe). `fixtures/patches/*.diff`: known-good and known-bad reference patches; regenerate with `python -m security.fixtures.patches.regenerate`. `fixtures/advisories/`: a saved OSV record with attribution. `fixtures/sbom/`: a demo SBOM that deliberately pins an old Werkzeug.

## Authorization boundary (`allowlist.py`, `sandbox.py`)

- Tests address targets **by ID**. There is no "scan this URL" input. Base URLs must use a loopback host or one of the compose names `demo-app` / `patch-target`, and they must resolve to loopback or private addresses. Link-local addresses, such as cloud metadata, are refused.
- Redirects are never followed, proxies are ignored, and response bodies are capped at 256 KB.
- Only registered test IDs run (`registry.py`).
- Patches may only **modify** allowlisted files (`app.py`). Creates, deletes, renames, mode changes, traversal paths and oversized diffs are refused. Hunks must apply with exact context. Added lines are linted against process, network, dynamic-code and destructive file-system APIs. Patched code is staged in a temp directory, and the original source is never touched.
- In Docker mode, code and fixtures are mounted read-only and the root FS is read-only. All capabilities are dropped, `no-new-privileges` is set, the container runs as a non-root user with 256 MB memory, 0.5 CPU and 64 pids, and the port is published on 127.0.0.1 only. No Docker socket is mounted.
- Secret-looking strings are redacted from artifacts and events. Evidence IDs are derived from observations, so the same observations always give the same ID. Artifacts are write-once and re-hashed by `verify_integrity`.

## Negative test matrix → tests

| Brief item | Test |
|---|---|
| Stale client flag evaluation | `test_flag_cache_lag_is_not_reported_as_contained` |
| Alias route still invokes vulnerable handler | `test_alias_route_bypassing_flag_is_caught` |
| Route variants that bypass naive matching | `route_variants` probed in every containment run |
| Fallback leaking fixture data | the `safe_fallback` check in every containment run |
| Flagsmith/app failure or timeout | `test_unreachable_target_is_infrastructure_error` |
| Patch secure but breaks behaviour | `test_patch_that_breaks_search_fails` |
| Patch touching a file outside the allowlist | `test_outside_allowlist_refused_at_submission`, `test_file_outside_allowlist_rejected` |
| Mismatched revision | `test_revision_mismatch_runs_nothing`, `test_stale_revision_runs_nothing` |
| Scanner finding without reproduction → suspected | `test_finding_without_reproduction_stays_suspected` |
| CVE match never reproduced | `test_affected_version_is_suspected_never_reproduced` |
| Non-allowlisted hosts | `test_non_allowlisted_targets_are_refused`, `test_redirects_are_not_followed` |

## Known limitations

- **Demo-bound.** There are two planted bugs, on declared routes only. Routes missing from the manifest are not probed, and a pass is not a general security guarantee.
- **The local sandbox is not isolation.** With `KSX_ALLOW_LOCAL_SANDBOX=1`, patched code runs as a host subprocess (127.0.0.1, scrubbed environment, lint-gated diff). Use it on dev machines only. Demos should use Docker.
- **Docker mode keeps a network namespace** so its port can be reached, which means egress is not blocked. The patch lint lowers the risk but does not remove it. Future work: run the probe driver inside an `--internal` network.
- **Docker mode is not yet run on this machine** (Docker is not installed here). `test_sqli_fix_in_docker` covers it and skips without a daemon.
- **On Windows hosts, CPU, memory and time limits are not enforced** for local mode beyond the request and launch timeouts.
- **The `/health` flag readback depends on the app reporting its real evaluation honestly.** The verifier also checks the `X-KSX-Variant` header and the actual responses, so a dishonest health endpoint alone cannot produce `contained`.
- **CVE data is a saved fixture.** Refresh it before the demo. Matches are relevance only; exploitability is never claimed.

## Cleanup

Delete `artifacts/` and `.ksx-fixture/`. Sandbox temp directories and containers are removed after each run (`docker ps --filter ancestor=ksx-sandbox:latest` should be empty).

## Credits

The oracle approach, the boolean-difference check and the Docker runtime pattern are adapted from ExhibitA (same author), re-implemented standalone here, with no dependency on it.
