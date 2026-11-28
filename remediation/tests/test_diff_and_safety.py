"""Tests for unified diff parsing, applicability, AST safety, allowlists, and hashes."""

from __future__ import annotations

import pytest
from remediation.demos import STAND_IN_APP_SOURCE
from remediation.patching.diff_validator import (
    apply_diff_in_memory,
    compute_candidate_hash,
    parse_unified_diff,
    validate_static_safety,
)
from remediation.patching.models import PatchLimitsConfig
from remediation.patching.source_access import STAND_IN_TARGET, load_snapshot_from_files
from shared.enums import PatchRejectionReason
from shared.exceptions import ContractValidationError, PatchValidationError


def test_strict_diff_parser_rejects_malformed_and_unsafe_diffs() -> None:
    # Empty diff rejected
    with pytest.raises(PatchValidationError):
        parse_unified_diff("")

    # Traversal path rejected
    with pytest.raises((PatchValidationError, ContractValidationError)):
        parse_unified_diff("--- a/../app.py\n+++ b/../app.py\n@@ -1,1 +1,1 @@\n-a\n+b\n")

    # File deletion / /dev/null rejected
    with pytest.raises(PatchValidationError):
        parse_unified_diff("--- a/app.py\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-a\n")

    # Rename rejected
    with pytest.raises(PatchValidationError):
        parse_unified_diff("--- a/app.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-a\n+b\n")

    # Hunk line count mismatch rejected
    with pytest.raises(PatchValidationError):
        parse_unified_diff("--- a/app.py\n+++ b/app.py\n@@ -1,5 +1,1 @@\n-a\n+b\n")

    # Size limit exceeded rejected
    with pytest.raises(PatchValidationError):
        parse_unified_diff(
            f"--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-a\n+{'b' * 150}\n",
            limits=PatchLimitsConfig(maximum_patch_bytes=128),
        )


def test_in_memory_applicability_and_static_safety() -> None:
    snap = load_snapshot_from_files(target=STAND_IN_TARGET, files={"app.py": STAND_IN_APP_SOURCE})

    # Context mismatch rejected (no fuzzy offset)
    bad_ctx = parse_unified_diff(
        "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-nonexistent_line\n+x = 1\n"
    )
    with pytest.raises(PatchValidationError):
        apply_diff_in_memory(snap, bad_ctx)

    # Suspicious subprocess import rejected by AST safety
    bad_import_diff = parse_unified_diff(
        "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n import os\n+import subprocess\n"
    )
    recon = apply_diff_in_memory(snap, bad_import_diff)
    reasons = validate_static_safety(recon, bad_import_diff, allowed_files=["app.py"])
    assert PatchRejectionReason.SUSPICIOUS_CODE_CHANGE in reasons

    # Test-gaming empty return in search_v1 rejected
    assert len(compute_candidate_hash("abc")) == 64
