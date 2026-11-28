from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from security import patching
from security.patching import PatchRejected

from .conftest import SOURCE_DIR

PATCHES = Path(__file__).resolve().parents[1] / "fixtures" / "patches"
ALLOWED = {"app.py"}


def _tree(tmp_path) -> Path:
    d = tmp_path / "code"
    shutil.copytree(SOURCE_DIR, d, ignore=shutil.ignore_patterns("__pycache__"))
    return d


def test_sqli_fix_applies_and_touches_only_app(tmp_path):
    d = _tree(tmp_path)
    touched = patching.apply(d, (PATCHES / "sqli_fix.diff").read_text(), ALLOWED)
    assert touched == ["app.py"]
    text = (d / "app.py").read_text()
    assert "+ q +" not in text and 'execute(sql, (f"%{q}%",))' in text
    assert (SOURCE_DIR / "app.py").read_text().count("+ q +") == 1  # original untouched


def test_file_outside_allowlist_rejected():
    with pytest.raises(PatchRejected, match="outside the patch allowlist"):
        patching.validate((PATCHES / "outside_allowlist.diff").read_text(), ALLOWED)


def test_denied_api_rejected():
    with pytest.raises(PatchRejected, match="denied API"):
        patching.validate((PATCHES / "denied_api.diff").read_text(), ALLOWED)


@pytest.mark.parametrize("header", [
    "--- a/../app.py\n+++ b/../app.py", "--- /etc/passwd\n+++ /etc/passwd",
    "--- a/C:/x/app.py\n+++ b/C:/x/app.py", "--- /dev/null\n+++ b/app.py",
    "--- a/app.py\n+++ b/other.py",
])
def test_dangerous_paths_rejected(header):
    diff = header + "\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    with pytest.raises(PatchRejected):
        patching.validate(diff, ALLOWED | {"other.py"})


def test_context_mismatch_rejected(tmp_path):
    d = _tree(tmp_path)
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-this line does not exist\n+x\n"
    with pytest.raises(PatchRejected, match="does not match"):
        patching.apply(d, diff, ALLOWED)


def test_removed_line_starting_with_dashes_is_not_a_header(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("a\n-- sql comment\nb\n")
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,2 @@\n a\n--- sql comment\n b\n"
    patching.apply(tmp_path, diff, ALLOWED)
    assert f.read_text() == "a\nb\n"


def test_truncated_and_oversized_rejected():
    with pytest.raises(PatchRejected):
        patching.parse("--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n a\n")
    with pytest.raises(PatchRejected, match="size"):
        patching.parse("x" * (patching.MAX_DIFF_BYTES + 1))
