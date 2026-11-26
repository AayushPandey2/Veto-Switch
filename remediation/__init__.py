"""Killswitch X — Remediation and Recovery Intelligence package boundary."""

from remediation.patch_agent import EvidenceGroundedPatchEngineer
from remediation.patching import (
    PLATFORM_DEMO_TARGET,
    REGISTERED_PATCH_TARGETS,
    STAND_IN_TARGET,
    PatchGenerationContext,
    PatchGenerationOutcome,
    PatchLimitsConfig,
    PatchTargetDescriptor,
    SourceSnapshot,
    build_patch_context,
    compute_candidate_hash,
    load_snapshot_from_files,
    parse_unified_diff,
    serialize_patch_dashboard,
    validate_patch_proposal,
)

__all__ = [
    "PLATFORM_DEMO_TARGET",
    "REGISTERED_PATCH_TARGETS",
    "STAND_IN_TARGET",
    "EvidenceGroundedPatchEngineer",
    "PatchGenerationContext",
    "PatchGenerationOutcome",
    "PatchLimitsConfig",
    "PatchTargetDescriptor",
    "SourceSnapshot",
    "build_patch_context",
    "compute_candidate_hash",
    "load_snapshot_from_files",
    "parse_unified_diff",
    "serialize_patch_dashboard",
    "validate_patch_proposal",
]
