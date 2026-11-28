"""CLI for the security lane.

  python -m security serve-target [--port 5001] [--nonce N]   run the stand-in demo target (seeded)
  python -m security flags search_v1=off [--dir D]           flip a stand-in flag (simulates Flagsmith)
  python -m security verify sqli_search --phase before [--target demo] [--incident inc-demo]
  python -m security scan [--target demo]
  python -m security patch-test security/fixtures/patches/sqli_fix.diff --tests sqli_search,functional_search
  python -m security cve [--refresh GHSA-...]
  python -m security artifacts inc-demo
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from security import cve_matcher, sandbox, scanner, seed
from security.evidence import ArtifactStore
from security.exploit_verifier import run_phase

DEFAULT_FIXTURE_DIR = Path(".ksx-fixture")


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_serve_target(a) -> int:
    fx = seed.build(a.dir, nonce=a.nonce)
    env = {**os.environ, **fx.env(), "KSX_PORT": str(a.port), "KSX_HOST": "127.0.0.1"}
    print(f"stand-in target on http://127.0.0.1:{a.port}  (fixture dir {fx.base_dir}, nonce {fx.nonce})")
    print("DEMO / SYNTHETIC DATA. Deliberately vulnerable: keep it on 127.0.0.1.")
    return subprocess.call([sys.executable, str(sandbox.SOURCES["stand_in"]["source_dir"] / "app.py")], env=env)


def cmd_flags(a) -> int:
    path = Path(a.dir) / "flags.json"
    flags = json.loads(path.read_text(encoding="utf-8"))
    for item in a.assignments:
        k, _, v = item.partition("=")
        flags[k] = v.lower() in {"on", "true", "1"}
    path.write_text(json.dumps(flags), encoding="utf-8")
    _print(flags)
    return 0


def cmd_verify(a) -> int:
    res = run_phase(a.phase, a.incident, a.test_id, a.target, revision=a.revision)
    _print(res.model_dump())
    return 0 if res.outcome not in {"infrastructure_error", "not_run", "revision_mismatch"} else 2


def cmd_scan(a) -> int:
    findings, events = scanner.scan_demo_sync(a.target)
    _print({"findings": [f.model_dump() for f in findings], "events": [e.model_dump() for e in events]})
    return 0


def cmd_patch_test(a) -> int:
    diff = Path(a.diff).read_text(encoding="utf-8")
    rev = sandbox.base_revision()
    pid = a.patch_id or f"patch-{uuid.uuid4().hex[:8]}"
    sandbox.PatchStore().submit(pid, diff, rev, a.incident)
    report = sandbox.run_patch_tests_sync(pid, rev, a.tests.split(","), mode=a.mode)
    _print(report)
    return 0 if report["status"] == "test_passed" else 1


def cmd_cve(a) -> int:
    if a.refresh:
        _print(cve_matcher.refresh_fixture(a.refresh))
        return 0
    _print([f.model_dump() for f in cve_matcher.scan_requirements()])
    return 0


def cmd_artifacts(a) -> int:
    store = ArtifactStore()
    _print({"manifest": [r.model_dump() for r in store.manifest(a.incident)],
            "integrity": store.verify_integrity(a.incident)})
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m security")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve-target"); s.add_argument("--port", type=int, default=5001)
    s.add_argument("--dir", default=str(DEFAULT_FIXTURE_DIR)); s.add_argument("--nonce", default="0000demo")
    s.set_defaults(fn=cmd_serve_target)

    s = sub.add_parser("flags"); s.add_argument("assignments", nargs="+")
    s.add_argument("--dir", default=str(DEFAULT_FIXTURE_DIR)); s.set_defaults(fn=cmd_flags)

    s = sub.add_parser("verify"); s.add_argument("test_id")
    s.add_argument("--phase", choices=["before", "after_containment", "after_patch"], default="before")
    s.add_argument("--target", default="demo"); s.add_argument("--incident", default="inc-demo")
    s.add_argument("--revision"); s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("scan"); s.add_argument("--target", default="demo"); s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("patch-test"); s.add_argument("diff"); s.add_argument("--tests", required=True)
    s.add_argument("--patch-id"); s.add_argument("--incident", default="inc-demo")
    s.add_argument("--mode", choices=["auto", "docker", "local"], default="auto"); s.set_defaults(fn=cmd_patch_test)

    s = sub.add_parser("cve"); s.add_argument("--refresh"); s.set_defaults(fn=cmd_cve)

    s = sub.add_parser("artifacts"); s.add_argument("incident"); s.set_defaults(fn=cmd_artifacts)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
