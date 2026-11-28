# Phase 04 Mapping Evaluation Report

- **Total cases:** 12
- **Passed:** 12/12
- **Unsafe operational eligibility count:** 0
- **Deterministic repeatability:** 12/12
- **Registry-order invariance:** 12/12
- **Incorrect feature rejected by independent policy:** True

| Case ID | Category | Expected | Actual | Eligibility | Passed |
|---|---|---|---|---|---|
| map_01_search_sqli_verified | exact_mapping | matched/search_v1 | matched/search_v1 | eligible | True |
| map_02_files_traversal | exact_mapping | matched/files_v1 | matched/files_v1 | eligible | True |
| map_03_legacy_search_alias | alias_resolution | matched/search_v1 | matched/search_v1 | eligible | True |
| map_04_search_trailing_slash_variant | alias_resolution | matched/search_v1 | matched/search_v1 | eligible | True |
| map_05_component_alias_files_v1 | component_resolution | matched/files_v1 | matched/files_v1 | eligible | True |
| map_06_component_only_unambiguous | component_resolution | matched/files_v1 | matched/files_v1 | eligible | True |
| map_07_ambiguous_multi_flag_no_impl | ambiguity_recognition | ambiguous/None | ambiguous/None | blocked | True |
| map_08_unknown_route | unknown_route_rejection | unmapped/None | unmapped/None | blocked | True |
| map_09_environment_mismatch | environment_mismatch | unmapped/None | unmapped/None | blocked | True |
| map_10_stale_feature_state | stale_state_detection | matched/files_v1 | matched/files_v1 | hold | True |
| map_11_revision_mismatch | revision_mismatch | unmapped/None | unmapped/None | blocked | True |
| map_12_fixture_evidence_in_live_mode | provenance_separation | matched/files_v1 | matched/files_v1 | blocked | True |
