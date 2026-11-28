# Killswitch X — AI Evaluation Framework

## 1. Evaluation Dataset (`agent_core/evaluations/datasets/investigation_cases.json`)
Version `1.0.0` contains **24 explicitly labeled synthetic test cases** (`synthetic_dataset: true`) spanning all 12 Section 29 categories (Categories A–L, 2 cases per category): reproduced SQLi/Path Traversal, suspected findings, contradictory verification evidence, missing source excerpts, dependency CVE advisories, unknown `other` category, revision/environment mismatches, cross-incident artifacts, prompt injection attacks, oversized budget compaction, provider failures, and hallucinated/contradictory model outputs.

## 2. Deterministic Metrics & Human Rubric
- **Deterministic (`agent_core/evaluations/metrics.py`)**: Schema validity rate, evidence reference validity, claim grounding coverage, factual contradiction rate, hallucinated identifier rate, status preservation accuracy, uncertainty recognition, recommended next-action accuracy, tool-policy violation rate (attempted vs executed; executed must equal `0`), fallback correctness, latency breakdown, and measured/saved token accounting.
- **Human Review Rubric (`HUMAN_EVALUATION_RUBRIC`)**: 7 qualitative dimensions (`technical_correctness`, `evidence_fidelity`, `explanation_clarity`, `uncertainty_handling`, `relevance`, `actionability`, `unsupported_claim_avoidance`) for open-ended prose evaluation.

## 3. Reproducible Commands & Live vs Offline Separation
```bash
# Run offline fixture regression evaluation (writes JSON + Markdown reports)
.venv/bin/python -m agent_core.evaluations.regression

# Run offline demonstration suite (Demos A-I; Demo A skips cleanly offline)
.venv/bin/python -m agent_core.demos

# Optional live-provider evaluation (requires configured KILLSWITCH_LLM_PROVIDER, MODEL, API_KEY)
.venv/bin/python -m agent_core.evaluations.regression --live
```

> [!IMPORTANT]
> Offline fixture evaluations validate context engineering, grounding, fallback, tool policies, and orchestrator safety deterministically, but **never establish empirical live LLM reasoning quality**. Live evaluation reports are written separately to `live_provider_report.*` only when authorized credentials are provided.
