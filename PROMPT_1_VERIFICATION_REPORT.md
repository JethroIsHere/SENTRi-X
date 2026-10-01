# SENTRi-X: Prompt 1 Verification and Corrections Report

**Date**: 1 October 2026 (Readiness Review Checkpoint: Commit `6a6a2e8`)  
**Status**: All Training-Data Corrections Resolved | Environment Verified | Prompt 2 (Full Retraining) Remains ON HOLD  
**Test Suite**: 75/75 tests passed (`tests/run_all_tests.py` suites T1–T13)  
**Notebook Executions**: 6/6 rewritten notebooks executed cleanly from fresh namespaces (with real CNN and RF models)  
**Environment Preflight**: `PASS` (`--require-tf` verified with TensorFlow 2.21.0 on Python 3.11.0)  
**Live Hardware Database**: Preserved (143 flows in `data/sentrix.db` intact)  

---

## 1. Summary of Completed Fixes (Readiness Review `6a6a2e8`)

| Review Finding | Review Evidence & Defect | Status | Resolution Implementation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **1. Sampling Excludes Later Data & Alters Evaluation Population** | Adapters stopped chunk reads early once 50/50 class quotas were filled. Rows in later chunks/files were completely unconsidered (e.g. 0 rows sampled from File 2 of ToN; latest selected first-file duration was row 498). BoT used a hardcoded benign slice `skiprows=range(1, 576884)`. Artificial 50/50 balance was applied before splitting, changing the holdout population. | **RESOLVED** | Implemented uniform Algorithm R reservoir sampling (`ReservoirBuffer` in `sentrix_ml/sampler.py`) across all chunks of all files. Removed all hardcoded row position skips. Streams full population (22.3M ToN, 3.67M BoT, 2.83M CIC). Preserves natural source prevalence in validation and test holdouts; balancing is restricted to training subsets only. Traversal metadata records `files_considered`, per-file SHA-256 hashes, `source_class_counts`, and exclusions. | `test_item9_reservoir_sampling_across_complete_multi_file_population`<br>`test_item2_adapters_reject_label_only_csv`<br>`sentrix_ml.preflight` |
| **2. Duplicate Separation & Lineage Declared but Not Implemented** | `SplitManifest` included `duplicate_group_policy="keep_first_disjoint"` and `source_file_hashes`, but splitting remained row-level random. 100 rows from 10 repeated records retained all 100 rows across both train and test. Candidate packages exported empty `source_file_hashes: {}`, `source_revision: ""`, and lacked partition flow IDs. Adaptation did not persist `source_candidate_manifest_hash`. | **RESOLVED** | Implemented `duplicate_group_policy="keep_first_disjoint"` in `sentrix_ml/splits.py`. Identifies duplicate 5-tuple flow groups (`src_ip:src_port->dst_ip:dst_port/proto`), keeps the first instance, drops duplicates into `exclusion_reasons["duplicate_rows_excluded"]`, and assigns entire groups to partitions so zero duplicate groups cross partitions. Populates `train_flow_ids`, `val_flow_ids`, `test_flow_ids`, and `source_file_hashes`. Enforces non-empty git SHA `source_revision` and adaptation `source_candidate_manifest_hash` across all training pipelines and package validators. | `test_item10_duplicate_group_policy_keep_first_disjoint`<br>`test_item10_end_to_end_training_persists_lineage_and_adaptation_source_hash`<br>`test_item3_package_validation_rejects_wrong_schema_and_classes` |
| **3. Notebooks Execution & Interfaces** | Earlier rewritten notebooks encountered parameter name and split mismatches. | **RESOLVED** | Rewrote all 6 notebooks to use actual package functions: `stratified_split`, `train_rf`, `train_cnn`, `hybrid_predict`, `compute_multimode_metrics`, `run_train_omni`. All 6 execute end-to-end cleanly with real CNN and RF training. | `tests/test_notebook_executions.py`<br>(6/6 notebooks pass) |
| **4. Backend Deployment Validation & Parity** | Strict deployment validation must reject smoke/mock packages and unfitted pipelines, while maintaining offline/backend prediction parity. | **RESOLVED** | Enforced `strict_deployable=True` across backend loading and activation. Unconditionally validates `is_fitted`, RF, and CNN. Offline and backend prediction parity verified across RF, CNN, and Hybrid modes. | `test_item3_backend_loader_rejects_unfitted_pipeline`<br>`test_t8_offline_backend_parity_all_modes` |
| **5. Metrics & XAI Provenance Gate** | Evaluation metrics and explanation artifacts must be cryptographically bound to models. | **RESOLVED** | `/api/model-metrics` verifies `file_sha256(eval_path) == manifest.evaluation_hash`. XAI provenance enforces matching `model_hash` on both sides. Legacy unprovenanced files completely removed. | `test_item4_api_model_metrics_tampering_rejected`<br>`test_item7_shap_without_hash_rejected_for_hashed_active_model` |

---

## 2. Environment Verification & Preflight Evidence

### Environment Specifications
- **Operating System**: Windows (PowerShell)
- **Python**: 3.11.0 (in `.\venv`)
- **TensorFlow**: **2.21.0** (verified installed, CPU execution operational)
- **Scikit-Learn**: 1.8.0
- **Pandas**: 3.0.1
- **NumPy**: 2.4.3
- **Joblib**: 1.5.3
- **Psutil**: 7.2.2
- **Host Total RAM**: 13.83 GB | **Available RAM**: ~1.63 GB
- **Disk Free Space**: ~2.09 GB (Total: 474.72 GB)
- **Live Hardware SQLite Database (`data/sentrix.db`)**: 143 records in `Network_Flows` verified intact.

### Preflight Command Execution
Executed command requiring real TensorFlow and traversing complete dataset populations:
```bash
python -m sentrix_ml.preflight --require-tf
```

### Preflight Output
```text
===========================================================================
           SENTRi-X ML Pipeline: Preflight Verification
           Schema: 28f-v2 (28 features) | Scope: ALL
===========================================================================

[1] Environment & Dependencies:
  - python_version        : 3.11.0
  - numpy                 : 2.4.3
  - pandas                : 3.0.1
  - scikit-learn          : 1.8.0
  - joblib                : 1.5.3
  - psutil                : 7.2.2
  - tensorflow            : 2.21.0
  - ram_total_gb          : 13.83
  - ram_available_gb      : 1.63
  - disk_free_gb          : 2.09

[2] Raw Datasets & Schema Adapters:
  * TON_IOT: [READY]
      file_count: 23
      total_size_mb: 3216.2
      sample_file: Network_dataset_1.csv
      adapter_test: PASS (shape=(50, 28), labels={1: np.int64(49), 0: np.int64(1)})
      source_class_counts: {'0': 795511, '1': 21542641}
      files_considered: 23 files (Network_dataset_1.csv through Network_dataset_23.csv)
      source_file_hashes: 23 verified SHA-256 digests
      selection_policy: reservoir_sampling
      exclusions: {'invalid_or_missing_required_numerics': 869}
  * BOT_IOT: [READY]
      file_count: 4
      total_size_mb: 970.0
      sample_file: UNSW_2018_IoT_Botnet_Full5pc_1.csv
      adapter_test: PASS (shape=(50, 28), labels={1: np.int64(50)})
      source_class_counts: {'0': 477, '1': 3668045}
      files_considered: 4 files (UNSW_2018_IoT_Botnet_Full5pc_1.csv through 4.csv)
      source_file_hashes: 4 verified SHA-256 digests
      selection_policy: reservoir_sampling
      ip_bytes_policy: exclude
      exclusions: {}
      unresolved_mappings: []
  * CIC_IDS2017: [READY]
      file_count: 8
      total_size_mb: 843.7
      sample_file: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
      adapter_test: PASS (shape=(50, 28), labels={0: np.int64(38), 1: np.int64(12)})
      source_class_counts: {'0': 2272982, '1': 557646}
      files_considered: 8 files
      source_file_hashes: 8 verified SHA-256 digests
      selection_policy: reservoir_sampling
      duration_unit: seconds
      exclusions: {'invalid_or_missing_required_numerics': 115}

===========================================================================
PREFLIGHT STATUS: READY FOR TRAINING (ALL)
===========================================================================
```

---

## 3. Test Suite Execution Results (T1–T13)

Command executed:
```bash
python tests/run_all_tests.py
```

### Complete Test Results Matrix
```text
======================================================================
       SENTRi-X ML Pipeline Corrections — Test Suite (T1-T13)
======================================================================

Category                                      | Total | Pass  | Fail  | Status
----------------------------------------------------------------------
T1: Split Isolation                           | 4     | 4     | 0     | PASS
T2: Encoding & Alignment                      | 5     | 5     | 0     | PASS
T3: Training / Live Equivalence               | 2     | 2     | 0     | PASS
T4: Transformation Coverage                   | 4     | 4     | 0     | PASS
T5: Hybrid Regression (Broadcast Fix)         | 3     | 3     | 0     | PASS
T6: Classification Boundaries & Alert Gate    | 3     | 3     | 0     | PASS
T7: Artifact Packaging & Hash Validation      | 5     | 5     | 0     | PASS
T8: Prediction Parity                         | 1     | 1     | 0     | PASS
T9: Metrics Provenance                        | 4     | 4     | 0     | PASS
T10: XAI Consistency & Provenance             | 3     | 3     | 0     | PASS
T11: Existing Behavior Regression             | 4     | 4     | 0     | PASS
T12: Prompt 1 Review Regression Checks        | 31    | 31    | 0     | PASS
T13: Rewritten Notebook Executions            | 6     | 6     | 0     | PASS
----------------------------------------------------------------------
Total Tests: 75 | Passed: 75 | Failed: 0 | Time: 517.23s
======================================================================
ALL TESTS PASSED SUCCESSFULLY!
```

---

## 4. Separation of Verification Gates

To maintain strict scientific and engineering honesty, pipeline checks are categorized into verified software verifications, blocked full-scale training runs, and external hardware trials:

### A. Verified (Passed & Proven)
1. **Multi-File Reservoir Sampling (Algorithm R)**:
   - Evaluated across complete dataset populations.
   - Preserves natural source prevalence in holdout partitions (e.g. ~10% attack prevalence in synthetic multi-file test fixture preserved, not forced to 50/50).
   - Samples late files and late attack categories without truncation or early exit.
   - Removed unverified row-slice assumptions (`skiprows` in BoT-IoT).
2. **Duplicate Group Isolation & Partition Disjointness**:
   - `duplicate_group_policy="keep_first_disjoint"` drops duplicate flow records prior to splitting.
   - Group-level stratification guarantees zero duplicate 5-tuple groups cross between train, validation, or test partitions.
   - Verified by test `test_item10_duplicate_group_policy_keep_first_disjoint` (100 rows containing 10 duplicate groups drops 90 rows; partitions are mathematically disjoint).
3. **End-to-End Lineage & Provenance Tracking**:
   - Split manifests record `source_file_hashes` and exact partition flow IDs (`train_flow_ids`, `val_flow_ids`, `test_flow_ids`).
   - Candidate packages store git commit hash in `source_revision`.
   - Adaptation packages record and enforce `source_candidate_manifest_hash`.
   - Verified by `test_item10_end_to_end_training_persists_lineage_and_adaptation_source_hash`.
4. **Real TensorFlow CNN Integration**:
   - TensorFlow 2.21.0 environment verified.
   - Real 1D-CNN architectures build, train, save (`cnn.h5`), reload, and predict.
   - Standalone CNN, RF, and Hybrid probability fusion verified.
   - Offline vs backend prediction parity verified.
5. **Notebook Executions**:
   - All 6 rewritten notebooks (`01`, `03`, `04`, `06`, `07`, `10`) execute cleanly from fresh namespaces using real model branches.

### B. Blocked (Held Off By Deliberate Design)
1. **Full-Scale Multi-Million-Row Retraining**:
   - Full dataset retraining across 22.3M ToN flows, 3.67M BoT flows, and 2.83M CIC flows is **BLOCKED / KEPT ON HOLD**.
   - Host environment has ~1.63 GB available RAM and ~2.09 GB free disk space. A full-scale training run would trigger memory exhaustion or disk write errors.
   - Requires dedicated execution in a high-capacity environment (>= 16 GB RAM, >= 30 GB free storage).

### C. Not Run (Future Scope Outside Prompt 1)
1. **Candidate Activation to Production**: Active deployment is kept untouched. Candidate packages remain isolated in candidate directories (`models/candidates/`).
2. **Physical Sensor Hardware Trials**: Live packet sniffing on Raspberry Pi edge hardware and live hardware attack injections are separate milestones.
3. **Database Mutation**: Active production database `data/sentrix.db` remains intact with 143 hardware flow records.

---

## 5. Prompt 2 Handoff & Governance

- **Decision**: **Prompt 2 remains ON HOLD**.
- **Assessment**:
  All Prompt 1 algorithmic, architectural, and data integrity prerequisites are now fully satisfied and tested.
  Before initiating Prompt 2 (full retraining & model activation):
  1. Acknowledge and approve the verified reservoir sampling protocol and duplicate group isolation policy.
  2. Provision a high-capacity execution environment (>= 16 GB RAM, >= 30 GB free storage) for the multi-gigabyte dataset training artifacts.
  3. Authorize full retraining as a distinct, deliberate step.
