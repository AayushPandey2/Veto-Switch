"""Regenerate the reference patch fixtures from the current stand-in app.

Run after editing security/stand_in_app/app.py:  python -m security.fixtures.patches.regenerate

These are KNOWN-GOOD / KNOWN-BAD reference patches for testing the patch runner.
They are fixtures, not model output.
"""

from __future__ import annotations

import difflib
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = HERE.parents[1] / "stand_in_app" / "app.py"

VULN_SQL = '''    # DELIBERATELY VULNERABLE (demo only): user input concatenated into SQL.
    sql = ("SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE '%"
           + q + "%' ORDER BY title")
    return db().execute(sql).fetchall()
'''
FIXED_SQL = '''    sql = "SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE ? ORDER BY title"
    return db().execute(sql, (f"%{q}%",)).fetchall()
'''
BROKEN_SQL = '''    # "Fixed" by refusing every query: blocks the exploit but breaks search.
    return []
'''
VULN_FILES = '''    # DELIBERATELY VULNERABLE (demo only): no normalization or root check.
    path = os.path.join(DOC_ROOT, name)
    with open(path, encoding="utf-8") as f:
'''
FIXED_FILES = '''    root = os.path.realpath(DOC_ROOT)
    path = os.path.realpath(os.path.join(root, name))
    if not name or os.path.commonpath([root, path]) != root or not os.path.isfile(path):
        raise ValueError("path outside document root")
    with open(path, encoding="utf-8") as f:
'''
DENIED = '''    import subprocess  # a patch must not add process APIs
    sql = "SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE ? ORDER BY title"
    return db().execute(sql, (f"%{q}%",)).fetchall()
'''


def _diff(old: str, new: str, name: str = "app.py") -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        fromfile=f"a/{name}", tofile=f"b/{name}"))


def main() -> None:
    src = APP.read_text(encoding="utf-8")
    assert VULN_SQL in src and VULN_FILES in src, "stand-in app changed; update the snippets above"
    out = {
        "sqli_fix.diff": _diff(src, src.replace(VULN_SQL, FIXED_SQL)),
        "traversal_fix.diff": _diff(src, src.replace(VULN_FILES, FIXED_FILES)),
        "sqli_fix_breaks_search.diff": _diff(src, src.replace(VULN_SQL, BROKEN_SQL)),
        "denied_api.diff": _diff(src, src.replace(VULN_SQL, DENIED)),
    }
    dockerfile = (APP.parent / "Dockerfile").read_text(encoding="utf-8")
    out["outside_allowlist.diff"] = _diff(dockerfile, dockerfile.replace("USER 10001", "USER root"), "Dockerfile")
    for name, text in out.items():
        (HERE / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {name} ({len(text)} bytes)")


if __name__ == "__main__":
    main()
