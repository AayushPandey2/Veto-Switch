"""Code revision identity for a target source tree.

Must stay byte-for-byte compatible with `tree_revision` in the demo app, which
reports its own revision on /health. A result is only trusted when the revision
the sandbox computed, the revision the app reports, and the revision the caller
asked for all agree.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def tracked(p: Path) -> bool:
    return p.is_file() and (p.suffix in {".py", ".txt"} or p.name == "Dockerfile")


def tree_revision(root: str | Path) -> str:
    root = Path(root)
    h = hashlib.sha256()
    for p in sorted(root.iterdir()):
        if not tracked(p):
            continue
        content = p.read_bytes().replace(b"\r\n", b"\n")
        h.update(p.name.encode() + b"\0")
        h.update(hashlib.sha256(content).hexdigest().encode() + b"\n")
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
