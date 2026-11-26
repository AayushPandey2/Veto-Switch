"""Deterministic offline evaluator for Phase 05 Blast Radius & Containment Strategist."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from shared.config import load_dependency_graph, load_route_registry
from shared.enums import (
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    MappingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import FeatureState, Finding, MappingResult

from agent_core.containment_strategist import DeterministicContainmentStrategist
from agent_core.context import FixedClock

DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parent / "datasets" / "blast_radius_cases.json"
)
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent / "reports"


async def run_blast_radius_evaluation(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> dict[str, Any]:
    """Run deterministic Phase 05 evaluation and persist JSON + Markdown reports."""
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = payload["cases"]
    registry = load_route_registry()
    graph = load_dependency_graph()
    reversed_graph = graph.model_copy(
        update={
            "nodes": list(reversed(graph.nodes)),
            "edges": list(reversed(graph.edges)),
        }
    )
    now = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)
    strategist = DeterministicContainmentStrategist(
        clock=FixedClock(now), registry=registry, fixture_mode=True
    )

    results: list[dict[str, Any]] = []
    passed_cases = 0
    unsafe_recommendations = 0
    order_invariant_count = 0

    for idx, case in enumerate(cases):
        status = FindingStatus(case["finding_status"])
        finding = Finding(
            finding_id=f"fnd_eval_br_{idx:02d}",
            incident_id=f"inc_eval_br_{idx:02d}",
            category=VulnerabilityCategory.SQL_INJECTION,
            affected_route=case["route"],
            affected_component=case["component"],
            severity=VulnerabilitySeverity.HIGH,
            status=status,
            evidence_ids=[f"art_eval_br_{idx:02d}"] if status == FindingStatus.REPRODUCED else [],
            repository_revision=registry.application_revision,
            environment=case["environment"],
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        m_status = MappingStatus(case["mapping_status"])
        mapping = MappingResult(
            finding_id=finding.finding_id,
            mapping_status=m_status,
            affected_route=case["route"],
            matched_component=case["component"],
            candidate_flags=(
                [case["selected_flag"]] if case["selected_flag"] else ["search_v1", "search_v2"]
            ),
            selected_flag=case["selected_flag"],
            registry_version=registry.registry_version,
            mapping_rationale="Evaluation fixture mapping.",
            evidence_ids=list(finding.evidence_ids),
            manual_review_required=m_status != MappingStatus.MATCHED,
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
                observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
            )
            for s in case["feature_states"]
        ]

        a1 = await strategist.analyze_containment(finding, mapping, graph, states)
        a2 = await strategist.analyze_containment(
            finding, mapping, reversed_graph, list(reversed(states))
        )

        rec_target = a1.recommended_option.proposed_target if a1.recommended_option else None
        rec_strat = (
            a1.recommended_option.strategy_type.value if a1.recommended_option else None
        )
        has_proposal = a1.proposal is not None

        order_inv = (
            (a1.recommended_option.proposed_target if a1.recommended_option else None)
            == (a2.recommended_option.proposed_target if a2.recommended_option else None)
            and (a1.recommended_option.relative_policy_score if a1.recommended_option else None)
            == (a2.recommended_option.relative_policy_score if a2.recommended_option else None)
        )
        if order_inv:
            order_invariant_count += 1

        if not case["expected_proposal"] and has_proposal:
            unsafe_recommendations += 1

        ok = (
            has_proposal == case["expected_proposal"]
            and rec_strat == case["expected_strategy"]
            and rec_target == case["expected_target"]
            and order_inv
        )
        if ok:
            passed_cases += 1

        results.append(
            {
                "case_id": case["case_id"],
                "passed": ok,
                "has_proposal": has_proposal,
                "recommended_strategy": rec_strat,
                "recommended_target": rec_target,
                "order_invariant": order_inv,
            }
        )

    total = len(cases)
    report: dict[str, Any] = {
        "dataset_version": payload["dataset_version"],
        "total_cases": total,
        "passed_cases": passed_cases,
        "failed_cases": total - passed_cases,
        "accuracy": round(passed_cases / total, 4) if total else 0.0,
        "unsafe_recommended_executable_options": unsafe_recommendations,
        "graph_order_invariance": f"{order_invariant_count}/{total}",
        "results": results,
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "blast_radius_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    md_lines = [
        "# Phase 05 Blast Radius & Containment Evaluation Report",
        "",
        f"- **Total cases:** {total}",
        f"- **Passed:** {passed_cases}/{total}",
        f"- **Unsafe recommended executable options:** {unsafe_recommendations}",
        f"- **Graph-order invariance:** {order_invariant_count}/{total}",
        "",
        "| Case ID | Proposal | Strategy | Target | Order Invariant | Passed |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        md_lines.append(
            f"| {r['case_id']} | {r['has_proposal']} | {r['recommended_strategy']} | "
            f"{r['recommended_target']} | {r['order_invariant']} | {r['passed']} |"
        )
    (reports_dir / "blast_radius_report.md").write_text(
        "\n".join(md_lines) + "\n", encoding="utf-8"
    )
    return report


def main() -> int:
    report = asyncio.run(run_blast_radius_evaluation())
    print(
        f"Blast radius evaluation finished passed={report['passed_cases']}/{report['total_cases']} "
        f"unsafe_recommendations={report['unsafe_recommended_executable_options']}"
    )
    return 0 if report["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
