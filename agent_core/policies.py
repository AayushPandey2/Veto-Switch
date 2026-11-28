"""Deterministic workflow policies validating injected AI and remediation outputs.

AI subsystems (investigator, feature mapper, containment strategist, patch
engineer, release manager) are untrusted producers until their structured outputs
pass deterministic policy checks against the authoritative registry, incident
identity, and evidence rules.
"""

from __future__ import annotations

from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    MappingStatus,
    PatchStatus,
    ProposalType,
)
from shared.exceptions import (
    AmbiguousMappingError,
    ContractValidationError,
    UnknownFeatureError,
)
from shared.schemas import (
    ContainmentProposal,
    Finding,
    InvestigationSummary,
    MappingResult,
    PatchProposal,
    RouteFlagRegistry,
)
from shared.serialization import sha256_bytes

from agent_core.mapping.registry import IndexedRouteRegistry
from agent_core.mapping.resolvers import compute_authoritative_candidates


def validate_investigation_output(
    summary: InvestigationSummary,
    *,
    finding: Finding,
) -> InvestigationSummary:
    """Validate that an injected investigator output matches the target finding & safety rules."""
    if summary.incident_id != finding.incident_id:
        raise ContractValidationError(
            "InvestigationSummary incident_id does not match Finding.",
            context={
                "expected_incident_id": finding.incident_id,
                "actual_incident_id": summary.incident_id,
            },
        )
    if summary.finding_id != finding.finding_id:
        raise ContractValidationError(
            "InvestigationSummary finding_id does not match Finding.",
            context={
                "expected_finding_id": finding.finding_id,
                "actual_finding_id": summary.finding_id,
            },
        )
    if (
        summary.finding_status == FindingStatus.REPRODUCED
        and finding.status == FindingStatus.SUSPECTED
    ):
        raise ContractValidationError(
            "InvestigationSummary cannot elevate suspected finding status to reproduced.",
            context={
                "authoritative_status": finding.status.value,
                "reported_status": summary.finding_status.value,
            },
        )
    if (
        summary.fallback_used
        and summary.reasoning_source != EvidenceProvenance.DETERMINISTIC_FALLBACK
    ):
        raise ContractValidationError(
            "Fallback InvestigationSummary must label reasoning_source='deterministic_fallback'.",
            context={"reasoning_source": summary.reasoning_source.value},
        )
    if summary.grounding_report is not None and not summary.grounding_report.overall_valid:
        raise ContractValidationError(
            "InvestigationSummary failed claim-level grounding checks and cannot be accepted.",
            context={
                "unknown_references": summary.grounding_report.unknown_references,
                "contradictions": summary.grounding_report.direct_factual_contradictions,
            },
        )
    return summary


def validate_mapping_output(
    mapping: MappingResult,
    *,
    finding: Finding,
    registry: RouteFlagRegistry,
    require_actionable: bool = True,
    expected_environment: str | None = None,
    expected_revision: str | None = None,
) -> MappingResult:
    """Validate an injected FeatureMapperAgent result against the authoritative registry."""
    if mapping.finding_id != finding.finding_id:
        raise ContractValidationError(
            "MappingResult finding_id does not match Finding.",
            context={"expected": finding.finding_id, "actual": mapping.finding_id},
        )
    if mapping.registry_version != registry.registry_version:
        raise ContractValidationError(
            "MappingResult used a stale or mismatched registry_version.",
            context={
                "expected": registry.registry_version,
                "actual": mapping.registry_version,
            },
        )
    if expected_environment and registry.environment != expected_environment:
        raise ContractValidationError(
            "Registry environment does not match expected environment.",
            context={"expected": expected_environment, "actual": registry.environment},
        )
    if (
        expected_revision
        and registry.application_revision
        and registry.application_revision != expected_revision
    ):
        raise ContractValidationError(
            "Registry application_revision does not match expected revision.",
            context={"expected": expected_revision, "actual": registry.application_revision},
        )
    if mapping.mapping_status == MappingStatus.AMBIGUOUS:
        if require_actionable:
            raise AmbiguousMappingError(
                "MappingResult is ambiguous and requires human disambiguation.",
                context={"candidate_flags": mapping.candidate_flags},
            )
        return mapping
    if mapping.mapping_status == MappingStatus.UNMAPPED or not mapping.selected_flag:
        if require_actionable:
            raise UnknownFeatureError(
                "Finding could not be mapped to any declared feature flag.",
                context={"affected_route": mapping.affected_route},
            )
        return mapping
    if mapping.selected_flag not in registry.declared_features:
        raise UnknownFeatureError(
            f"Mapped flag {mapping.selected_flag!r} is not declared in active registry.",
            context={"selected_flag": mapping.selected_flag},
        )

    indexed = IndexedRouteRegistry(registry)
    authoritative_candidates = compute_authoritative_candidates(
        indexed,
        route=mapping.affected_route or finding.affected_route,
        component=mapping.matched_component or finding.affected_component,
    )
    if mapping.selected_flag not in authoritative_candidates:
        raise ContractValidationError(
            f"Selected flag {mapping.selected_flag!r} is not semantically bound to "
            f"route={mapping.affected_route or finding.affected_route!r} / "
            f"component={mapping.matched_component or finding.affected_component!r}.",
            context={
                "selected_flag": mapping.selected_flag,
                "authoritative_candidates": authoritative_candidates,
            },
        )
    if require_actionable and mapping.manual_review_required:
        raise ContractValidationError(
            "Actionable mapping cannot proceed while manual_review_required=True.",
            context={"selected_flag": mapping.selected_flag},
        )
    if require_actionable and mapping.diagnostics is not None:
        eligibility = mapping.diagnostics.get("action_eligibility")
        if eligibility in {"hold", "blocked"}:
            raise ContractValidationError(
                f"Mapping action_eligibility={eligibility!r} blocks containment progression.",
                context={"selected_flag": mapping.selected_flag, "action_eligibility": eligibility},
            )
    return mapping


def validate_containment_proposal_output(
    proposal: ContainmentProposal,
    *,
    finding: Finding,
    mapping: MappingResult,
    registry: RouteFlagRegistry,
    require_v2_hash: bool = False,
    expected_environment: str | None = None,
) -> ContainmentProposal:
    """Validate an injected ContainmentStrategistAgent proposal before acceptance."""
    if proposal.incident_id != finding.incident_id:
        raise ContractValidationError(
            "ContainmentProposal incident_id does not match Finding.",
            context={"expected": finding.incident_id, "actual": proposal.incident_id},
        )
    if finding.status != FindingStatus.REPRODUCED:
        raise ContractValidationError(
            "ContainmentProposal requires a reproduced finding.",
            context={"finding_status": finding.status.value},
        )
    if mapping.mapping_status != MappingStatus.MATCHED or mapping.manual_review_required:
        raise ContractValidationError(
            "ContainmentProposal requires an actionable, matched MappingResult.",
            context={
                "mapping_status": mapping.mapping_status.value,
                "manual_review_required": mapping.manual_review_required,
            },
        )
    if require_v2_hash and proposal.hash_version != "v2":
        raise ContractValidationError(
            "Live containment proposal must use hardened hash_version='v2'.",
            context={"hash_version": proposal.hash_version},
        )
    if not proposal.verify_hash():
        raise ContractValidationError(
            "ContainmentProposal canonical SHA-256 proposal_hash is invalid.",
            context={"proposal_id": proposal.proposal_id},
        )
    if not proposal.approval_required:
        raise ContractValidationError(
            "ContainmentProposal must enforce approval_required=True.",
            context={"proposal_id": proposal.proposal_id},
        )
    if proposal.proposal_type != ProposalType.CONTAINMENT_FLAG_DISABLE:
        raise ContractValidationError(
            f"Unsupported autonomous proposal_type {proposal.proposal_type.value!r}.",
            context={"proposal_type": proposal.proposal_type.value},
        )
    if proposal.desired_enabled is not False:
        raise ContractValidationError(
            "Containment flag-disable proposal must set desired_enabled=False.",
            context={"desired_enabled": proposal.desired_enabled},
        )
    if proposal.environment != registry.environment:
        raise ContractValidationError(
            "ContainmentProposal environment does not match active registry.",
            context={"expected": registry.environment, "actual": proposal.environment},
        )
    if expected_environment and proposal.environment != expected_environment:
        raise ContractValidationError(
            "ContainmentProposal environment does not match incident environment.",
            context={"expected": expected_environment, "actual": proposal.environment},
        )
    if proposal.flag_name not in registry.declared_features:
        raise UnknownFeatureError(
            f"Proposed flag {proposal.flag_name!r} is not declared in active registry.",
            context={"flag_name": proposal.flag_name},
        )
    if mapping.selected_flag and proposal.flag_name != mapping.selected_flag:
        raise ContractValidationError(
            "ContainmentProposal flag_name differs from validated MappingResult flag.",
            context={"mapped": mapping.selected_flag, "proposed": proposal.flag_name},
        )
    return proposal


def validate_patch_proposal_output(
    proposal: PatchProposal,
    *,
    finding: Finding,
    expected_revision: str | None = None,
) -> PatchProposal:
    """Validate an injected PatchEngineerAgent proposal against incident & hash invariants."""
    if proposal.incident_id != finding.incident_id:
        raise ContractValidationError(
            "PatchProposal incident_id does not match Finding.",
            context={"expected": finding.incident_id, "actual": proposal.incident_id},
        )
    if proposal.finding_id != finding.finding_id:
        raise ContractValidationError(
            "PatchProposal finding_id does not match Finding.",
            context={"expected": finding.finding_id, "actual": proposal.finding_id},
        )
    if finding.status != FindingStatus.REPRODUCED:
        raise ContractValidationError(
            "PatchProposal requires a reproduced finding.",
            context={"finding_status": finding.status.value},
        )
    if expected_revision and proposal.source_revision != expected_revision:
        raise ContractValidationError(
            "PatchProposal source_revision does not match expected revision.",
            context={"expected": expected_revision, "actual": proposal.source_revision},
        )
    if proposal.status != PatchStatus.PATCH_PROPOSED:
        raise ContractValidationError(
            f"PatchProposal status must be 'patch_proposed', got {proposal.status.value!r}."
        )
    if not proposal.review_required:
        raise ContractValidationError("PatchProposal must enforce review_required=True.")
    expected_hash = sha256_bytes(proposal.unified_diff.replace("\r\n", "\n").encode("utf-8"))
    if proposal.candidate_content_hash != expected_hash:
        raise ContractValidationError(
            "PatchProposal candidate_content_hash does not match unified_diff bytes.",
            context={"expected": expected_hash, "actual": proposal.candidate_content_hash},
        )
    return proposal


def validate_patch_test_result_output(
    result: object,
    *,
    proposal: PatchProposal,
    required_tests: list[str] | None = None,
) -> object:
    """Validate an isolated PatchTestResult against candidate hash, revision, and required tests."""
    from shared.enums import TestExecutionStatus
    from shared.schemas import PatchTestResult

    if not isinstance(result, PatchTestResult):
        raise ContractValidationError("Expected a PatchTestResult instance.")
    if result.incident_id != proposal.incident_id:
        raise ContractValidationError(
            "PatchTestResult incident_id does not match PatchProposal.",
            context={"expected": proposal.incident_id, "actual": result.incident_id},
        )
    if result.patch_id != proposal.patch_id:
        raise ContractValidationError(
            "PatchTestResult patch_id does not match PatchProposal.",
            context={"expected": proposal.patch_id, "actual": result.patch_id},
        )
    if result.tested_candidate_hash != proposal.candidate_content_hash:
        raise ContractValidationError(
            "PatchTestResult tested_candidate_hash does not match PatchProposal.",
            context={
                "expected": proposal.candidate_content_hash,
                "actual": result.tested_candidate_hash,
            },
        )
    if result.isolation_metadata.get("mode") == "host":
        raise ContractValidationError(
            "PatchTestResult cannot be accepted from host execution mode."
        )
    if required_tests and result.overall_status == TestExecutionStatus.TEST_PASSED:
        outcomes_by_name = {o.test_name: o.status for o in result.individual_outcomes}
        missing = [
            tid
            for tid in required_tests
            if outcomes_by_name.get(tid) != TestExecutionStatus.TEST_PASSED
        ]
        if missing:
            raise ContractValidationError(
                "PatchTestResult omitted or failed mandatory tests.",
                context={"missing_or_failed_tests": missing},
            )
    return result
