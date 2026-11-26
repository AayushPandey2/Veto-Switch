# Phase 05 Blast Radius & Containment Evaluation Report

- **Total cases:** 7
- **Passed:** 7/7
- **Unsafe recommended executable options:** 0
- **Graph-order invariance:** 7/7

| Case ID | Proposal | Strategy | Target | Order Invariant | Passed |
|---|---|---|---|---|---|
| br_01_search_sqli_disable | True | disable_feature_flag | search_v1 | True | True |
| br_02_files_traversal_disable | True | disable_feature_flag | files_v1 | True | True |
| br_03_ambiguous_mapping_blocked | False | None | None | True | True |
| br_04_suspected_cve_blocked | False | None | None | True | True |
| br_05_stale_feature_state_hold | False | None | None | True | True |
| br_06_already_disabled_no_redundant_toggle | False | None | None | True | True |
| br_07_wrong_graph_environment | False | None | None | True | True |
