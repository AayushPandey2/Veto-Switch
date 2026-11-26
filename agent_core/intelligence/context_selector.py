"""Deterministic evidence-aware importance classification and priority selection."""

from __future__ import annotations

from enum import StrEnum

from shared.enums import ArtifactType, FindingStatus
from shared.schemas import ArtifactReference, Finding

from agent_core.intelligence.investigation_context import (
    AdvisoryContextItem,
    DependencyMetadataItem,
    SourceExcerpt,
)


class ContextImportance(StrEnum):
    """Context element classification tiers (Section 13 Stage 3)."""

    MANDATORY_EVIDENCE = "mandatory_evidence"
    RELEVANT_TECHNICAL = "relevant_technical"
    SUPPORTING_DEPENDENCY = "supporting_dependency"
    OPTIONAL_EXPLANATORY = "optional_explanatory"
    IRRELEVANT = "irrelevant"
    INCONSISTENT_UNTRUSTED = "inconsistent_untrusted"
    SENSITIVE = "sensitive"


def classify_artifact_importance(
    artifact: ArtifactReference, *, finding: Finding
) -> tuple[ContextImportance, int]:
    """Classify and score evidence artifacts so reproduction evidence outranks verbose logs."""
    if artifact.artifact_type == ArtifactType.REPRODUCTION_LOG:
        return ContextImportance.MANDATORY_EVIDENCE, 100
    if artifact.artifact_type == ArtifactType.REGRESSION_LOG:
        return ContextImportance.MANDATORY_EVIDENCE, 95
    if artifact.artifact_id in finding.evidence_ids:
        return ContextImportance.MANDATORY_EVIDENCE, 90
    if artifact.artifact_type in {ArtifactType.SCANNER_REPORT, ArtifactType.DEPLOYMENT_MANIFEST}:
        return ContextImportance.RELEVANT_TECHNICAL, 70
    return ContextImportance.OPTIONAL_EXPLANATORY, 40


def select_prioritized_artifacts(
    artifacts: list[ArtifactReference], *, finding: Finding
) -> list[ArtifactReference]:
    """Order artifacts deterministically by clinical relevance rather than arrival order."""
    scored = [
        (
            classify_artifact_importance(art, finding=finding)[1],
            art.artifact_id,
            art,
        )
        for art in artifacts
    ]
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored]


def select_relevant_excerpts(
    excerpts: list[SourceExcerpt], *, finding: Finding
) -> list[SourceExcerpt]:
    """Rank source excerpts matching the finding component/route above tangential files."""
    comp = finding.affected_component.lower()
    route_token = (finding.affected_route or "").strip("/").lower()

    def _score(ex: SourceExcerpt) -> tuple[int, str]:
        path_lower = ex.file_path.lower()
        reason_lower = ex.reason_for_inclusion.lower()
        score = 10
        if comp and (comp in path_lower or comp in reason_lower):
            score += 50
        if route_token and (route_token in path_lower or route_token in ex.code_excerpt.lower()):
            score += 30
        if finding.status == FindingStatus.REPRODUCED:
            score += 5
        return (-score, ex.file_id)

    return sorted(excerpts, key=_score)


def select_relevant_dependencies(
    deps: list[DependencyMetadataItem], *, finding: Finding
) -> list[DependencyMetadataItem]:
    """Prioritize dependencies linked directly to the affected component."""
    comp = finding.affected_component.lower()
    return sorted(
        deps,
        key=lambda d: (
            0 if comp in d.relevant_component.lower() or comp in d.dependency_name.lower() else 1,
            d.dependency_name,
        ),
    )


def select_relevant_advisories(
    advisories: list[AdvisoryContextItem], *, finding: Finding
) -> list[AdvisoryContextItem]:
    """Prioritize advisories referencing finding CVE IDs or affected component."""
    finding_cves = {c.upper() for c in finding.cve_ids}
    comp = finding.affected_component.lower()

    def _score(adv: AdvisoryContextItem) -> tuple[int, str]:
        overlap = bool(finding_cves.intersection({c.upper() for c in adv.cve_ids}))
        if overlap:
            return (0, adv.advisory_id)
        if comp in adv.package_name.lower():
            return (1, adv.advisory_id)
        return (2, adv.advisory_id)

    return sorted(advisories, key=_score)
