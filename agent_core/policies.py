"""Deterministic workflow policies validating injected AI and remediation outputs.

AI subsystems (investigator, feature mapper, containment strategist, patch
engineer, release manager) are untrusted producers until their structured outputs
pass deterministic policy checks against the authoritative registry, incident
identity, and evidence rules.
"""

from __future__ import annotations

from shared.enums import EvidenceProvenance, FindingStatus, MappingStatus
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
    RouteFlagRegistry,
)


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
    if mapping.mapping_status == MappingStatus.AMBIGUOUS:
        raise AmbiguousMappingError(
            "MappingResult is ambiguous and requires human disambiguation.",
            context={"candidate_flags": mapping.candidate_flags},
        )
    if mapping.mapping_status == MappingStatus.UNMAPPED or not mapping.selected_flag:
        raise UnknownFeatureError(
            "Finding could not be mapped to any declared feature flag.",
            context={"affected_route": mapping.affected_route},
        )
    if mapping.selected_flag not in registry.declared_features:
        raise UnknownFeatureError(
            f"Mapped flag {mapping.selected_flag!r} is not declared in active registry.",
            context={"selected_flag": mapping.selected_flag},
        )
    return mapping


def validate_containment_proposal_output(
    proposal: ContainmentProposal,
    *,
    finding: Finding,
    mapping: MappingResult,
    registry: RouteFlagRegistry,
) -> ContainmentProposal:
    """Validate an injected ContainmentStrategistAgent proposal before acceptance."""
    if proposal.incident_id != finding.incident_id:
        raise ContractValidationError(
            "ContainmentProposal incident_id does not match Finding.",
            context={"expected": finding.incident_id, "actual": proposal.incident_id},
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
    if proposal.environment != registry.environment:
        raise ContractValidationError(
            "ContainmentProposal environment does not match active registry.",
            context={"expected": registry.environment, "actual": proposal.environment},
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
