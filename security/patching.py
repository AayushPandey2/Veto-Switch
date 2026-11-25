"""Strict unified-diff validation and application for candidate patches.

Candidate patches (usually model-written) are untrusted input. Before anything
runs, a patch must: touch only allowlisted files, modify existing files only (no
creates/deletes/renames), stay under size limits, apply with exact context (line
offsets allowed, no fuzz), and pass a deny-list lint on added lines. The lint is
defence in depth, not a sandbox: the patched code still only runs inside one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_DIFF_BYTES = 64 * 1024
MAX_CHANGED_LINES = 400

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# Added lines may not introduce process, network, dynamic-code or destructive FS APIs.
DENY_ADDED = [
    r"\bsubprocess\b", r"\bsocket\b", r"\bctypes\b", r"\bos\.(system|popen|exec\w*|spawn\w*|fork|kill|remove|unlink|rmdir)\b",
    r"\beval\s*\(", r"\bexec\s*\(", r"__import__", r"\bimportlib\b", r"\bpickle\b", r"\bmarshal\b",
    r"\burllib\b", r"\brequests\b", r"\bhttpx\b", r"\bshutil\b", r"\bcompile\s*\(", r"\bbuiltins\b",
]


class PatchRejected(ValueError):
    pass


@dataclass
class Hunk:
    old_start: int
    lines: list[str] = field(default_factory=list)  # each starts with ' ', '-', '+'

    @property
    def old(self) -> list[str]:
        return [ln[1:] for ln in self.lines if ln[:1] in (" ", "-")]

    @property
    def new(self) -> list[str]:
        return [ln[1:] for ln in self.lines if ln[:1] in (" ", "+")]


@dataclass
class FilePatch:
    path: str
    hunks: list[Hunk] = field(default_factory=list)


def _clean_path(raw: str) -> str:
    p = raw.split("\t", 1)[0].strip()
    if p == "/dev/null":
        raise PatchRejected("creating or deleting files is not allowed")
    if p.startswith(("a/", "b/")):
        p = p[2:]
    if "\\" in p or re.match(r"^[A-Za-z]:", p) or p.startswith("/"):
        raise PatchRejected(f"path {raw!r} must be relative POSIX")
    pp = PurePosixPath(p)
    if any(part in ("..", ".", "") for part in pp.parts):
        raise PatchRejected(f"path {raw!r} contains traversal or empty segments")
    return pp.as_posix()


def parse(diff: str) -> list[FilePatch]:
    if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        raise PatchRejected("diff exceeds size limit")
    lines = diff.replace("\r\n", "\n").split("\n")
    files: list[FilePatch] = []
    cur: FilePatch | None = None
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith(("rename ", "new file", "deleted file", "Binary files", "GIT binary patch",
                          "old mode", "new mode", "copy ")):
            raise PatchRejected(f"unsupported diff operation: {' '.join(ln.split()[:2])}")
        if ln.startswith("--- "):
            if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                raise PatchRejected("malformed file header")
            old, new = _clean_path(ln[4:]), _clean_path(lines[i + 1][4:])
            if old != new:
                raise PatchRejected("renames are not allowed")
            cur = FilePatch(new)
            files.append(cur)
            i += 2
            continue
        m = _HUNK.match(ln)
        if not m:
            i += 1  # preamble ("diff --git", "index ...") or trailing text
            continue
        if cur is None:
            raise PatchRejected("hunk before file header")
        hunk = Hunk(int(m.group(1)))
        cur.hunks.append(hunk)
        old_n = int(m.group(2) or 1)
        new_n = int(m.group(4) or 1)
        i += 1
        # Consume exactly the line counts the header declares, so a removed line
        # that happens to start with "-- " is never mistaken for a file header.
        while old_n > 0 or new_n > 0:
            if i >= len(lines):
                raise PatchRejected("hunk is truncated")
            body = lines[i]
            i += 1
            if body.startswith("\\"):
                continue
            tag = body[:1] or " "
            if tag == " ":
                old_n, new_n = old_n - 1, new_n - 1
            elif tag == "-":
                old_n -= 1
            elif tag == "+":
                new_n -= 1
            else:
                raise PatchRejected("malformed hunk line")
            if old_n < 0 or new_n < 0:
                raise PatchRejected("hunk line counts do not match its header")
            hunk.lines.append(body if body else " ")
    if not files or not any(f.hunks for f in files):
        raise PatchRejected("diff contains no hunks")
    changed = sum(1 for f in files for h in f.hunks for ln in h.lines if ln[:1] in "+-")
    if changed > MAX_CHANGED_LINES:
        raise PatchRejected(f"diff changes {changed} lines (limit {MAX_CHANGED_LINES})")
    return files


def validate(diff: str, allowed_files: set[str]) -> list[FilePatch]:
    files = parse(diff)
    for f in files:
        if f.path not in allowed_files:
            raise PatchRejected(f"file {f.path!r} is outside the patch allowlist {sorted(allowed_files)}")
        for h in f.hunks:
            for ln in h.lines:
                if ln.startswith("+"):
                    for pat in DENY_ADDED:
                        if re.search(pat, ln):
                            raise PatchRejected(f"added line uses a denied API ({pat}) in {f.path}")
    return files


def _find(haystack: list[str], needle: list[str], hint: int) -> int:
    if not needle:
        return min(hint, len(haystack))
    starts = [i for i in range(len(haystack) - len(needle) + 1) if haystack[i:i + len(needle)] == needle]
    if not starts:
        return -1
    return min(starts, key=lambda s: abs(s - hint))


def apply(root: str | Path, diff: str, allowed_files: set[str]) -> list[str]:
    """Apply `diff` to files under `root` in place. Returns the touched paths."""
    root = Path(root).resolve()
    files = validate(diff, allowed_files)
    for f in files:
        target = (root / f.path).resolve()
        if root not in target.parents or not target.is_file():
            raise PatchRejected(f"{f.path!r} does not exist in the target tree")
        text = target.read_text(encoding="utf-8").replace("\r\n", "\n")
        trailing_nl = text.endswith("\n")
        content = text.split("\n")
        if trailing_nl:
            content = content[:-1]
        offset = 0
        for h in f.hunks:
            pos = _find(content, h.old, h.old_start - 1 + offset)
            if pos < 0:
                raise PatchRejected(f"hunk at line {h.old_start} of {f.path} does not match the base revision")
            content[pos:pos + len(h.old)] = h.new
            offset += len(h.new) - len(h.old)
        target.write_text("\n".join(content) + ("\n" if trailing_nl else ""), encoding="utf-8", newline="\n")
    return [f.path for f in files]
