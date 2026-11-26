"""Strict unified diff parser, in-memory applicability, AST static safety, and hash integrity."""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence

from shared.enums import PatchRejectionReason, PatchStatus
from shared.exceptions import ContractValidationError, PatchValidationError
from shared.schemas import PatchProposal
from shared.serialization import canonical_json, sha256_bytes, sha256_text
from shared.validation import validate_relative_safe_path

from remediation.patching.models import (
    MinimalityMetrics,
    ParsedFileDiff,
    ParsedHunk,
    ParsedUnifiedDiff,
    PatchGenerationContext,
    PatchLimitsConfig,
    SourceSnapshot,
)

_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*$")

_FORBIDDEN_IMPORTS: frozenset[str] = frozenset(
    {"subprocess", "socket", "urllib", "requests", "httpx", "ctypes", "pty", "telnetlib"}
)
_FORBIDDEN_CALL_NAMES: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})
_FORBIDDEN_ATTR_CALLS: frozenset[tuple[str, str]] = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "spawnl"),
        ("os", "spawnv"),
        ("os", "execv"),
        ("os", "execl"),
        ("shutil", "rmtree"),
    }
)


def compute_candidate_hash(unified_diff: str) -> str:
    """Compute canonical UTF-8 SHA-256 digest of ``unified_diff`` (LF-normalized)."""
    normalized = unified_diff.replace("\r\n", "\n")
    return sha256_bytes(normalized.encode("utf-8"))


def verify_candidate_hash(proposal: PatchProposal) -> bool:
    """Return True iff ``proposal.candidate_content_hash`` matches ``proposal.unified_diff``."""
    return proposal.candidate_content_hash == compute_candidate_hash(proposal.unified_diff)


def compute_candidate_manifest_fingerprint(
    proposal: PatchProposal,
    *,
    target_id: str,
    snapshot_fingerprint: str,
) -> str:
    """Compute immutable review manifest fingerprint binding metadata + diff hash."""
    return sha256_text(
        canonical_json(
            {
                "patch_id": proposal.patch_id,
                "incident_id": proposal.incident_id,
                "finding_id": proposal.finding_id,
                "target_id": target_id,
                "source_revision": proposal.source_revision,
                "snapshot_fingerprint": snapshot_fingerprint,
                "candidate_content_hash": proposal.candidate_content_hash,
                "allowed_files": sorted(proposal.allowed_files),
                "touched_files": sorted(proposal.touched_files),
                "required_tests": sorted(proposal.required_tests),
                "patch_origin": proposal.patch_origin.value,
            }
        )
    )


def _strip_diff_path(raw_header: str) -> str:
    path = raw_header.strip()
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return validate_relative_safe_path(path, field_name="diff_path")


def normalize_diff_wrapper(raw: str) -> str:
    """Strip a single markdown code-fence wrapper if present; reject competing fences."""
    text = raw.replace("\r\n", "\n").strip()
    if "```" not in text:
        return text
    lines = text.splitlines()
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip() == "```":
        inner = "\n".join(lines[1:-1]).strip()
        if "```" in inner:
            raise PatchValidationError(
                "Ambiguous multiple code blocks in unified diff.",
                context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
            )
        return inner
    raise PatchValidationError(
        "Malformed markdown fence around unified diff.",
        context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
    )


def parse_unified_diff(
    raw_diff: str,
    *,
    limits: PatchLimitsConfig | None = None,
) -> ParsedUnifiedDiff:
    """Strictly parse a unified diff and derive ``actual_touched_files``."""
    cfg = limits or PatchLimitsConfig()
    normalized = normalize_diff_wrapper(raw_diff)
    if not normalized.strip():
        raise PatchValidationError(
            "Unified diff is empty.",
            context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
        )
    if len(normalized.encode("utf-8")) > cfg.maximum_patch_bytes:
        raise PatchValidationError(
            f"Patch size exceeds maximum {cfg.maximum_patch_bytes} bytes.",
            context={"reason": PatchRejectionReason.PATCH_SIZE_LIMIT_EXCEEDED.value},
        )

    lines = normalized.splitlines()
    idx = 0
    parsed_files: list[ParsedFileDiff] = []
    seen_files: set[str] = set()
    total_added = 0
    total_removed = 0
    total_hunks = 0

    while idx < len(lines):
        line = lines[idx]
        unsupported_prefixes = (
            "GIT binary patch",
            "rename from ",
            "rename to ",
            "new file mode ",
            "deleted file mode ",
        )
        if line.startswith(unsupported_prefixes):
            raise PatchValidationError(
                f"Unsupported diff operation: {line!r}.",
                context={"reason": PatchRejectionReason.UNSUPPORTED_FILE_OPERATION.value},
            )
        if not line.startswith("--- "):
            if line.strip() == "" and not parsed_files:
                idx += 1
                continue
            raise PatchValidationError(
                f"Expected '--- ' header at line {idx + 1}, got {line!r}.",
                context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
            )
        if idx + 1 >= len(lines) or not lines[idx + 1].startswith("+++ "):
            raise PatchValidationError(
                "Missing '+++ ' header after '--- '.",
                context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
            )
        raw_old = lines[idx][4:]
        raw_new = lines[idx + 1][4:]
        if raw_old.strip() == "/dev/null" or raw_new.strip() == "/dev/null":
            raise PatchValidationError(
                "File creation and deletion are unsupported.",
                context={"reason": PatchRejectionReason.UNSUPPORTED_FILE_OPERATION.value},
            )
        old_path = _strip_diff_path(raw_old)
        new_path = _strip_diff_path(raw_new)
        if old_path != new_path:
            raise PatchValidationError(
                f"File rename {old_path!r} -> {new_path!r} is unsupported.",
                context={"reason": PatchRejectionReason.UNSUPPORTED_FILE_OPERATION.value},
            )
        if old_path in seen_files:
            raise PatchValidationError(
                f"Duplicate file section for {old_path!r}.",
                context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
            )
        seen_files.add(old_path)
        idx += 2

        hunks: list[ParsedHunk] = []
        last_old_end = 0
        while idx < len(lines) and not lines[idx].startswith("--- "):
            hline = lines[idx]
            m = _HUNK_HEADER_RE.match(hline)
            if not m:
                raise PatchValidationError(
                    f"Expected hunk header '@@ ... @@' at line {idx + 1}, got {hline!r}.",
                    context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
                )
            old_start = int(m.group(1))
            old_count = int(m.group(2)) if m.group(2) is not None else 1
            new_start = int(m.group(3))
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            if old_start <= last_old_end and last_old_end > 0:
                raise PatchValidationError(
                    f"Overlapping or out-of-order hunk in {old_path!r}.",
                    context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
                )
            idx += 1

            hunk_lines: list[str] = []
            seen_old = 0
            seen_new = 0
            while idx < len(lines):
                cur = lines[idx]
                if cur.startswith(("--- ", "@@ ")):
                    break
                if cur.startswith(" "):
                    seen_old += 1
                    seen_new += 1
                    hunk_lines.append(cur)
                elif cur.startswith("-"):
                    seen_old += 1
                    total_removed += 1
                    hunk_lines.append(cur)
                elif cur.startswith("+"):
                    seen_new += 1
                    total_added += 1
                    hunk_lines.append(cur)
                elif cur == r"\ No newline at end of file":
                    hunk_lines.append(cur)
                else:
                    raise PatchValidationError(
                        f"Unexpected diff content at line {idx + 1}: {cur!r}.",
                        context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
                    )
                idx += 1

            if seen_old != old_count or seen_new != new_count:
                raise PatchValidationError(
                    f"Hunk line count mismatch in {old_path!r}: "
                    f"expected (-{old_count}, +{new_count}), got (-{seen_old}, +{seen_new}).",
                    context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
                )
            last_old_end = old_start + max(old_count, 1) - 1
            hunks.append(
                ParsedHunk(
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    lines=hunk_lines,
                )
            )
            total_hunks += 1

        if not hunks:
            raise PatchValidationError(
                f"File {old_path!r} contains no hunks.",
                context={"reason": PatchRejectionReason.MALFORMED_UNIFIED_DIFF.value},
            )
        parsed_files.append(ParsedFileDiff(old_path=old_path, new_path=new_path, hunks=hunks))

    if len(parsed_files) > cfg.maximum_changed_files:
        raise PatchValidationError(
            f"Changed files ({len(parsed_files)}) exceed limit {cfg.maximum_changed_files}.",
            context={"reason": PatchRejectionReason.PATCH_SIZE_LIMIT_EXCEEDED.value},
        )
    if total_added + total_removed > cfg.maximum_changed_lines:
        raise PatchValidationError(
            f"Changed lines ({total_added + total_removed}) exceed limit "
            f"{cfg.maximum_changed_lines}.",
            context={"reason": PatchRejectionReason.PATCH_SIZE_LIMIT_EXCEEDED.value},
        )
    if total_hunks > cfg.maximum_hunks:
        raise PatchValidationError(
            f"Total hunks ({total_hunks}) exceed limit {cfg.maximum_hunks}.",
            context={"reason": PatchRejectionReason.PATCH_SIZE_LIMIT_EXCEEDED.value},
        )

    return ParsedUnifiedDiff(
        files=parsed_files,
        actual_touched_files=[f.new_path for f in parsed_files],
        added_lines=total_added,
        removed_lines=total_removed,
        total_hunks=total_hunks,
    )


def apply_diff_in_memory(
    snapshot: SourceSnapshot,
    parsed: ParsedUnifiedDiff,
) -> dict[str, str]:
    """Apply parsed diff strictly in memory with exact context matching (no fuzzy offsets)."""
    reconstructed = dict(snapshot.files)
    for file_diff in parsed.files:
        if file_diff.new_path not in reconstructed:
            raise PatchValidationError(
                f"Target file {file_diff.new_path!r} is not present in authorized snapshot.",
                context={"reason": PatchRejectionReason.PATCH_FILE_OUTSIDE_ALLOWLIST.value},
            )
        orig_lines = reconstructed[file_diff.new_path].splitlines()
        new_lines: list[str] = []
        cursor = 0  # 0-based index into orig_lines

        for hunk in file_diff.hunks:
            target_idx = max(hunk.old_start - 1, 0)
            if target_idx < cursor or target_idx > len(orig_lines):
                raise PatchValidationError(
                    f"Hunk start line {hunk.old_start} out of bounds for {file_diff.new_path!r}.",
                    context={"reason": PatchRejectionReason.PATCH_CONTEXT_MISMATCH.value},
                )
            new_lines.extend(orig_lines[cursor:target_idx])
            cursor = target_idx

            for hline in hunk.lines:
                if hline == r"\ No newline at end of file":
                    continue
                prefix = hline[0]
                content = hline[1:]
                if prefix in {" ", "-"}:
                    if cursor >= len(orig_lines) or orig_lines[cursor] != content:
                        raise PatchValidationError(
                            f"Exact context mismatch at {file_diff.new_path}:{cursor + 1}.",
                            context={"reason": PatchRejectionReason.PATCH_CONTEXT_MISMATCH.value},
                        )
                    if prefix == " ":
                        new_lines.append(content)
                    cursor += 1
                elif prefix == "+":
                    new_lines.append(content)

        new_lines.extend(orig_lines[cursor:])
        reconstructed[file_diff.new_path] = "\n".join(new_lines) + "\n"
    return reconstructed


def validate_static_safety(
    reconstructed: dict[str, str],
    parsed: ParsedUnifiedDiff,
    *,
    allowed_files: Sequence[str],
) -> list[PatchRejectionReason]:
    """Perform bounded AST inspection on reconstructed Python source (zero code execution)."""
    reasons: list[PatchRejectionReason] = []
    allowed_set = set(allowed_files)
    for fp in parsed.actual_touched_files:
        if fp not in allowed_set:
            reasons.append(PatchRejectionReason.PATCH_FILE_OUTSIDE_ALLOWLIST)
            continue
        if not fp.endswith(".py"):
            continue
        source = reconstructed.get(fp, "")
        try:
            tree = ast.parse(source, filename=fp)
        except SyntaxError:
            reasons.append(PatchRejectionReason.APPLICATION_CONTRACT_VIOLATION)
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in _FORBIDDEN_IMPORTS:
                        reasons.append(PatchRejectionReason.SUSPICIOUS_CODE_CHANGE)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_mod = node.module.split(".")[0]
                if root_mod in _FORBIDDEN_IMPORTS:
                    reasons.append(PatchRejectionReason.SUSPICIOUS_CODE_CHANGE)
            elif isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALL_NAMES) or (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and (node.func.value.id, node.func.attr) in _FORBIDDEN_ATTR_CALLS
                ):
                    reasons.append(PatchRejectionReason.SUSPICIOUS_CODE_CHANGE)
            elif (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "search_v1"
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Return)
                and isinstance(node.body[0].value, ast.List)
                and len(node.body[0].value.elts) == 0
            ):
                # Reject trivial test-gaming: `def search_v1(q): return []`
                reasons.append(PatchRejectionReason.APPLICATION_CONTRACT_VIOLATION)

    return sorted(set(reasons), key=lambda r: r.value)


def compute_minimality_metrics(
    parsed: ParsedUnifiedDiff,
    reconstructed: dict[str, str],
) -> MinimalityMetrics:
    """Compute explainable minimality metrics from parsed diff and reconstructed AST."""
    affected_fns: set[str] = set()
    for fdiff in parsed.files:
        src = reconstructed.get(fdiff.new_path, "")
        try:
            tree = ast.parse(src, filename=fdiff.new_path)
        except SyntaxError:
            continue
        changed_ranges = [
            (h.new_start, h.new_start + max(h.new_count, 1) - 1) for h in fdiff.hunks
        ]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_start = node.lineno
                fn_end = node.end_lineno or node.lineno
                if any(not (end < fn_start or start > fn_end) for start, end in changed_ranges):
                    affected_fns.add(f"{fdiff.new_path}:{node.name}")

    return MinimalityMetrics(
        modified_file_count=len(parsed.actual_touched_files),
        added_line_count=parsed.added_lines,
        removed_line_count=parsed.removed_lines,
        modified_line_count=parsed.added_lines + parsed.removed_lines,
        hunk_count=parsed.total_hunks,
        affected_function_count=len(affected_fns),
    )


def validate_patch_proposal(
    proposal: PatchProposal,
    context: PatchGenerationContext,
    *,
    limits: PatchLimitsConfig | None = None,
) -> PatchProposal:
    """Independent deterministic validator verifying a ``PatchProposal`` against context."""
    if proposal.incident_id != context.incident_id:
        raise ContractValidationError(
            "PatchProposal incident_id does not match PatchGenerationContext.",
            context={"expected": context.incident_id, "actual": proposal.incident_id},
        )
    if proposal.finding_id != context.finding.finding_id:
        raise ContractValidationError(
            "PatchProposal finding_id does not match Finding.",
            context={"expected": context.finding.finding_id, "actual": proposal.finding_id},
        )
    if proposal.source_revision != context.source_snapshot.source_revision:
        raise ContractValidationError(
            "PatchProposal source_revision does not match authorized SourceSnapshot.",
            context={
                "expected": context.source_snapshot.source_revision,
                "actual": proposal.source_revision,
                "reason": PatchRejectionReason.SOURCE_REVISION_MISMATCH.value,
            },
        )
    if proposal.status != PatchStatus.PATCH_PROPOSED:
        raise ContractValidationError(
            f"New candidate PatchProposal must have status='patch_proposed', "
            f"got {proposal.status.value!r}."
        )
    if not proposal.review_required:
        raise ContractValidationError("PatchProposal must enforce review_required=True.")
    if not verify_candidate_hash(proposal):
        raise ContractValidationError(
            "PatchProposal candidate_content_hash does not match unified_diff bytes.",
            context={"reason": PatchRejectionReason.CANDIDATE_HASH_MISMATCH.value},
        )
    if set(proposal.allowed_files) != set(context.target_descriptor.allowed_files):
        raise ContractValidationError(
            "PatchProposal allowed_files does not match authoritative target allowlist.",
            context={"reason": PatchRejectionReason.PATCH_FILE_OUTSIDE_ALLOWLIST.value},
        )

    parsed = parse_unified_diff(proposal.unified_diff, limits=limits)
    if sorted(parsed.actual_touched_files) != sorted(proposal.touched_files):
        raise ContractValidationError(
            "PatchProposal touched_files does not match files parsed from unified_diff.",
            context={"reason": PatchRejectionReason.TOUCHED_FILE_MISMATCH.value},
        )
    reconstructed = apply_diff_in_memory(context.source_snapshot, parsed)
    safety_issues = validate_static_safety(
        reconstructed, parsed, allowed_files=context.target_descriptor.allowed_files
    )
    if safety_issues:
        raise ContractValidationError(
            f"PatchProposal failed static safety checks: {[r.value for r in safety_issues]}.",
            context={"reasons": [r.value for r in safety_issues]},
        )
    return proposal
