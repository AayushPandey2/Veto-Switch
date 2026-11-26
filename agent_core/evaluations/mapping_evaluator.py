"""Deterministic offline evaluator for Phase 04 Vulnerability-to-Feature-Flag Mapping."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from shared.config import load_route_registry
from shared.enums import (
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    MappingActionEligibility,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ContractValidationError
from shared.schemas import FeatureState, Finding, MappingResult, RouteFlagRegistry

from agent_core.flag_mapper import DeterministicFlagMapper
from agent_core.mapping.models import MappingContext
from agent_core.policies import validate_mapping_output

DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parent / "datasets" / "mapping_cases.json"
)
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def _build_reversed_registry(registry: RouteFlagRegistry) -> RouteFlagRegistry:
    reversed_routes = [
        entry.model_copy(
            update={
                "flags": list(reversed(entry.flags)),
                "implementation_bindings": list(reversed(entry.implementation_bindings)),
            }
        )
        for entry in reversed(registry.routes)
    ]
    return registry.model_copy(
        update={
            "declared_features": list(reversed(registry.declared_features)),
            "routes": reversed_routes,
        }
    )


async def run_mapping_evaluation(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> dict[str, Any]:
    """Run deterministic Phase 04 mapping evaluation and write JSON + Markdown reports."""
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = payload["cases"]
    registry = load_route_registry()
    reversed_registry = _build_reversed_registry(registry)
    now = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)

    results: list[dict[str, Any]] = []
    passed_cases = 0
    unsafe_eligibility_count = 0
    order_invariant_count = 0
    repeatable_count = 0

    for idx, case in enumerate(cases):
        finding = Finding(
            finding_id=f"fnd_eval_map_{idx:02d}",
            incident_id=f"inc_eval_map_{idx:02d}",
            category=VulnerabilityCategory.SQL_INJECTION,
            affected_route=case["route"],
            affected_component=case["component"],
            severity=VulnerabilitySeverity.HIGH,
            status=FindingStatus(case["finding_status"]),
            evidence_ids=[f"art_eval_map_{idx:02d}"],
            repository_revision=case["application_revision"],
            environment=case["environment"],
            provenance=EvidenceProvenance(case["provenance"]),
        )
        states = [
            FeatureState(
                environment=case["environment"],
                feature_id=f"fs_{s['feature_name']}",
                feature_name=s["feature_name"],
                observation_status=FeatureObservationStatus(s["status"]),
                enabled=s["enabled"],
                observed_at=now - timedelta(seconds=s["age_seconds"]),
                state_version="v1",
                observation_source=EvidenceProvenance(
                    s.get("provenance", EvidenceProvenance.REFERENCE_FIXTURE.value)
                ),
            )
            for s in case.get("feature_states", [])
        ]
        ctx = MappingContext(
            finding=finding,
            observed_implementation=case.get("observed_implementation"),
            application_revision=case["application_revision"],
            environment=case["environment"],
            fixture_mode=bool(case["fixture_mode"]),
            evaluation_timestamp=now,
        )
        mapper = DeterministicFlagMapper(fixture_mode=bool(case["fixture_mode"]))
        out1 = await mapper.map_with_diagnostics(finding, registry, states, context=ctx)
        out2 = await mapper.map_with_diagnostics(finding, registry, states, context=ctx)
        out_rev = await mapper.map_with_diagnostics(
            finding, reversed_registry, list(reversed(states)), context=ctx
        )

        repeatable = (
            out1.mapping_result.selected_flag == out2.mapping_result.selected_flag
            and out1.mapping_result.mapping_status == out2.mapping_result.mapping_status
            and out1.diagnostics.action_eligibility == out2.diagnostics.action_eligibility
        )
        order_invariant = (
            out1.mapping_result.selected_flag == out_rev.mapping_result.selected_flag
            and out1.mapping_result.mapping_status == out_rev.mapping_result.mapping_status
            and out1.mapping_result.candidate_flags == out_rev.mapping_result.candidate_flags
        )
        if repeatable:
            repeatable_count += 1
        if order_invariant:
            order_invariant_count += 1

        actual_status = out1.mapping_result.mapping_status.value
        actual_flag = out1.mapping_result.selected_flag
        actual_elig = out1.diagnostics.action_eligibility.value

        # Unsafe eligibility: expected blocked/hold but got eligible
        if (
            case["expected_eligibility"] in {"blocked", "hold"}
            and out1.diagnostics.action_eligibility == MappingActionEligibility.ELIGIBLE
        ):
            unsafe_eligibility_count += 1

        case_passed = (
            actual_status == case["expected_status"]
            and actual_flag == case["expected_flag"]
            and actual_elig == case["expected_eligibility"]
            and repeatable
            and order_invariant
        )
        if case_passed:
            passed_cases += 1

        results.append(
            {
                "case_id": case["case_id"],
                "category": case["category"],
                "passed": case_passed,
                "actual_status": actual_status,
                "actual_flag": actual_flag,
                "actual_eligibility": actual_elig,
                "repeatable": repeatable,
                "order_invariant": order_invariant,
            }
        )

    # Also verify incorrect-feature rejection by independent policy validator
    bad_finding = Finding(
        finding_id="fnd_eval_bad_flag",
        incident_id="inc_eval_bad_flag",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_eval_bad_flag"],
    )
    bad_mapping = MappingResult(
        finding_id=bad_finding.finding_id,
        mapping_status="matched",  # type: ignore[arg-type]
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["files_v1"],
        selected_flag="files_v1",
        registry_version=registry.registry_version,
        mapping_rationale="Deliberately wrong flag for policy check.",
        evidence_ids=["art_eval_bad_flag"],
        manual_review_required=False,
    )
    incorrect_flag_rejected = False
    try:
        validate_mapping_output(bad_mapping, finding=bad_finding, registry=registry)
    except ContractValidationError:
        incorrect_flag_rejected = True

    total = len(cases)
    report: dict[str, Any] = {
        "dataset_version": payload["dataset_version"],
        "total_cases": total,
        "passed_cases": passed_cases,
        "failed_cases": total - passed_cases,
        "accuracy": round(passed_cases / total, 4) if total else 0.0,
        "unsafe_operational_eligibility_count": unsafe_eligibility_count,
        "deterministic_repeatability": f"{repeatable_count}/{total}",
        "registry_order_invariance": f"{order_invariant_count}/{total}",
        "incorrect_feature_rejected": incorrect_flag_rejected,
        "results": results,
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "mapping_report.json"
    md_path = reports_dir / "mapping_report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    md_lines = [
        "# Phase 04 Mapping Evaluation Report",
        "",
        f"- **Total cases:** {total}",
        f"- **Passed:** {passed_cases}/{total}",
        f"- **Unsafe operational eligibility count:** {unsafe_eligibility_count}",
        f"- **Deterministic repeatability:** {repeatable_count}/{total}",
        f"- **Registry-order invariance:** {order_invariant_count}/{total}",
        f"- **Incorrect feature rejected by independent policy:** {incorrect_flag_rejected}",
        "",
        "| Case ID | Category | Expected | Actual | Eligibility | Passed |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        exp = next(c for c in cases if c["case_id"] == r["case_id"])
        md_lines.append(
            f"| {r['case_id']} | {r['category']} | "
            f"{exp['expected_status']}/{exp['expected_flag']} | "
            f"{r['actual_status']}/{r['actual_flag']} | "
            f"{r['actual_eligibility']} | {r['passed']} |"
        )
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = asyncio.run(run_mapping_evaluation())
    print(
        f"Mapping evaluation finished passed={report['passed_cases']}/{report['total_cases']} "
        f"unsafe_eligibility={report['unsafe_operational_eligibility_count']} "
        f"incorrect_flag_rejected={report['incorrect_feature_rejected']}"
    )
    return 0 if report["failed_cases"] == 0 and report["incorrect_feature_rejected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
