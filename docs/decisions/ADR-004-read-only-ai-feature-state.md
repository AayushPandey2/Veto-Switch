# ADR-004: Read-Only AI Access to Feature State

## Context
Flagsmith feature flags control live application traffic. Granting AI modules direct write/toggle credentials or mutation interfaces creates an unacceptable blast radius if an LLM hallucinates or suffers prompt injection.

## Decision
Expose only the strictly read-only `FeatureStateReader` protocol (`get_feature_state`, `list_declared_features`, `get_environment_metadata`, `get_targeting_configuration`) to AI modules, and isolate privileged tokens inside `PlatformPrivilegedSettings`.

## Alternatives
1. Passing Flagsmith management API keys directly to `agent_core`.
2. Wrapping Flagsmith mutations inside an AI tool-calling function.

## Rationale
Least privilege guarantees AI layers can inspect flag configuration and verify readbacks without ever possessing the capability to mutate production or staging flags autonomously.

## Consequences
- `agent_core` emits `ContainmentProposal` objects rather than executing flag changes.
- Automated contract tests enforce that `FeatureStateReader` exposes zero mutation verbs.

## Known Limitations
Containment latency includes human review and platform executor dispatch rather than instant unapproved execution.
