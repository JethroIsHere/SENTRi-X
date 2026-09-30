# SENTRi-X: Prompt 1 Verification and Corrections Report

**Date**: 30 September 2026 (Follow-Up Checkpoint: Commit `a780334`)  
**Status**: All 6 Review Blockers Resolved | Prompt 2 (Full Retraining) Remains ON HOLD  
**Test Suite**: 72/72 tests passed (`tests/run_all_tests.py` suites T1–T13)  
**Notebook Executions**: 6/6 rewritten notebooks executed cleanly from fresh namespaces  
**Live Hardware Database**: Preserved (143 flows in `data/sentrix.db` intact)  

---

## 1. Summary of Completed Fixes (Follow-up Review `a780334`)

| Blocker Area | Review Evidence & Finding | Status | Resolution Implementation | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **1. Notebooks Execution** | All 6 rewritten notebooks (`01`, `03`, `04`, `06`, `07`, `10`) failed on import (`split_dataset`, `random_state`, `run_omni_training`), 15% vs 20% test fraction, test set passed as val data, lack of cross-domain evaluation in `07`. | **RESOLVED** | Rewrote all 6 notebooks to use actual package functions: `stratified_split`, `train_rf`, `train_cnn`, `hybrid_predict`, `compute_multimode_metrics`, `run_train_omni`. Unpacked `(X, y, info)` tuple, enforced 80/20 train/test splits, preserved validation set isolation, and restored cross-domain evaluation in notebook 07. Clean executions verified on bounded data. | `tests/test_notebook_executions.py`<br>(6/6 notebooks pass) |
| **2. Preflight & Raw Data Acceptance** | Preflight accepted CSVs with only `label` (fabricated 28 all-zero features). Prefix sampling on ordered files produced single-class samples. BoT-IoT per-IP aggregate bytes (`TnBPSrcIP`/`TnBPDstIP`) appeared as unresolved warnings. | **RESOLVED** | Added `MANDATORY_RAW_COLUMNS` to `load_ton_iot`, `load_bot_iot`, and `load_cic_ids2017`—rejects label-only CSVs. Implemented multi-class chunked sampling across files (targeting 50% benign / 50% attack). In `load_bot_iot`, added `ip_bytes_policy: Literal["exclude", "aggregate_proxy"] = "exclude"`, eliminating aggregate rate contamination under `28f-v2`. Preflight inspects class counts and strictly reports `FAILED` if single-class. | `test_item2_adapters_reject_label_only_csv`<br>`test_item2_chunked_sampling_covers_both_classes_on_ordered_file`<br>`test_item2_preflight_fails_on_single_class_data`<br>`test_item2_bot_iot_ip_bytes_policy_exclude` |
| **3. Backend Strict Deployment Validation** | `load_models_and_data` called `validate_package` with `strict_deployable=False`, accepting smoke/mock packages in omni slot. Unfitted preprocessing pipelines could bypass checks. Adaptation source candidate lacked strict validation. | **RESOLVED** | Enforced `strict_deployable=True` at every backend and activation loading boundary (`load_models_and_data`, `manage_package.py`). Unconditionally validated `staged_pipeline.is_fitted` and `staged_rf is not None`. `train_adaptation.py` strictly validates source package with `strict_deployable=(run_type == "full")` and `target_domain="ton_iot"`. Implemented transactional activation rollback and API failed-switch restoration with temporary DB. | `test_item3_backend_loader_rejects_mock_smoke_and_target_mismatch`<br>`test_item3_backend_loader_rejects_unfitted_pipeline`<br>`test_item3_failed_switch_rollback_via_api`<br>`test_item8_adaptation_source_provenance_enforced` |
| **4. Metrics Integrity Checks** | Tampered evaluation files on disk (e.g. changing accuracy to 0.1234) were served by `/api/model-metrics` because disk hash was never checked against `manifest.evaluation_hash`. Missing/cleared hashes still allowed metrics availability. | **RESOLVED** | `/api/model-metrics` verifies `file_sha256(eval_path) == engine.manifest.evaluation_hash`. Returns `available: False` on tampering or hash mismatch. `format_metrics_for_api` enforces non-null, matching `rf_hash`, `cnn_hash`, `preprocessor_hash`, and domain. | `test_item4_api_model_metrics_tampering_rejected`<br>`test_item4_metrics_missing_hashes_rejected` |
| **5. Canonical Encoding & XAI Gaps** | `encode_dataframe` accepted negative numeric values while `build_feature_row` rejected them. For `{"proto": None, "proto_tcp": 1}`, batch encoding rejected it as contradiction while single-row accepted it. `XAIProvenance.matches` treated missing hashes as compatible. Backend loaded legacy explanation files. | **RESOLVED** | Unified validation across `build_feature_row` and `encode_dataframe`: both strictly reject negative numeric values and accept `proto=None` with explicit one-hot flags. Added batch vs single-row numerical equivalence tests. Strict XAI provenance requires non-empty `model_hash` on both sides. Wired backend LIME to `create_lime_explainer` and removed legacy unprovenanced explanation artifacts. | `test_item5_negative_numerics_rejected_by_both_encoders`<br>`test_item5_none_proto_with_one_hot_accepted_by_both`<br>`test_item5_comprehensive_batch_vs_single_row_equivalence`<br>`test_item7_shap_without_hash_rejected_for_hashed_active_model` |
| **6. Reproducibility & Lineage Tracking** | `SplitManifest` lacked durable source file hashes, original row identities, and duplicate policy. Activation lacked transactional rollback. Report lacked current resource measurements. | **RESOLVED** | Added `source_file_hashes`, `duplicate_group_policy="keep_first_disjoint"`, and `exclusion_reasons` to `SplitManifest`. `manage_package.py` implements atomic activation with automatic rollback on validation error. Fresh resource measurements and verified test logs documented below. | `test_item1_mock_artifacts_cannot_pass_deployment_validation`<br>`test_item3_package_validation_rejects_wrong_schema_and_classes` |

---

## 2. Preflight Real-Data Verification Evidence

Command executed:
```bash
python -m sentrix_ml.preflight
```

Output:
```text
===========================================================================
           SENTRi-X ML Pipeline: Preflight Verification
           Schema: 28f-v2 (28 features) | Scope: ALL
===========================================================================

[1] Environment & Dependencies:
  - python_version        : 3.14.0
  - numpy                 : 2.3.5
  - pandas                : 3.0.3
  - scikit-learn          : 1.8.0
  - joblib                : 1.5.3
  - psutil                : 7.2.2
  - tensorflow            : NOT INSTALLED (mock fallback allowed for smoke tests only)
  - ram_total_gb          : 13.83
  - ram_available_gb      : 0.93
  - disk_free_gb          : 2.04

[2] Raw Datasets & Schema Adapters:
  * TON_IOT: [READY]
      file_count: 23
      total_size_mb: 3216.2
      sample_file: Network_dataset_1.csv
      adapter_test: PASS (shape=(50, 28), labels={0: np.int64(25), 1: np.int64(25)})
      exclusions: {}
  * BOT_IOT: [READY]
      file_count: 4
      total_size_mb: 970.0
      sample_file: UNSW_2018_IoT_Botnet_Full5pc_1.csv
      adapter_test: PASS (shape=(50, 28), labels={0: np.int64(25), 1: np.int64(25)})
      ip_bytes_policy: exclude
      exclusions: {}
      unresolved_mappings: []
  * CIC_IDS2017: [READY]
      file_count: 8
      total_size_mb: 843.7
      sample_file: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
      adapter_test: PASS (shape=(50, 28), labels={0: np.int64(25), 1: np.int64(25)})
      duration_unit: seconds
      exclusions: {}

===========================================================================
PREFLIGHT STATUS: READY FOR TRAINING (ALL)
===========================================================================
```

When executed with `--require-tf` (mandatory for full training):
```bash
python -m sentrix_ml.preflight --require-tf
```

Output:
```text
===========================================================================
           SENTRi-X ML Pipeline: Preflight Verification
           Schema: 28f-v2 (28 features) | Scope: ALL
===========================================================================

[1] Environment & Dependencies:
  - python_version        : 3.14.0
  - numpy                 : 2.3.5
  - pandas                : 3.0.3
  - scikit-learn          : 1.8.0
  - joblib                : 1.5.3
  - psutil                : 7.2.2
  - tensorflow            : MISSING [BLOCKING for full training]
  - ram_total_gb          : 13.83
  - ram_available_gb      : 1.06
  - disk_free_gb          : 2.15

[2] Raw Datasets & Schema Adapters:
  * TON_IOT: [READY] (shape=(50, 28), labels={0: 25, 1: 25})
  * BOT_IOT: [READY] (shape=(50, 28), labels={0: 25, 1: 25}, ip_bytes_policy: exclude)
  * CIC_IDS2017: [READY] (shape=(50, 28), labels={0: 25, 1: 25}, duration_unit: seconds)

===========================================================================
PREFLIGHT STATUS: FAILED — BLOCKING ISSUES DETECTED
  ! Environment dependencies missing.
===========================================================================
(Exit code: 1)
```

---

## 3. Test Suite Execution Results (T1–T13)

Command executed:
```bash
python tests/run_all_tests.py
```

Results:
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
T12: Prompt 1 Review Regression Checks        | 28    | 28    | 0     | PASS
T13: Rewritten Notebook Executions            | 6     | 6     | 0     | PASS
----------------------------------------------------------------------
Total Tests: 72 | Passed: 72 | Failed: 0 | Time: 44.28s
======================================================================
ALL TESTS PASSED SUCCESSFULLY!
```

---

## 4. Notebook Execution Verification Evidence

All 6 rewritten notebooks were executed from fresh, clean namespaces against the exact committed package interfaces using bounded fixtures (`tests/test_notebook_executions.py`):

1. **`01_ETL_Pipeline_ToN_IoT.ipynb`**:
   - Uses `load_ton_iot`, `stratified_split` with 80% train / 20% test holdout (and 10% validation).
   - Fits `PreprocessingPipeline` strictly on train partition. No data leakage.
   - Output: `X_train: (3600, 28)`, `X_val: (400, 28)`, `X_test: (1000, 28)`.

2. **`03_Model_Training_CNN_ToN_IoT.ipynb`**:
   - Uses `build_cnn_model`, `train_cnn`.
   - Isolates validation set from test holdout.
   - Cleanly falls back to smoke execution when TensorFlow is absent.

3. **`04_Hybrid_Ensemble_Fusion_ToN_IoT.ipynb`**:
   - Uses `train_rf`, `predict_rf`, `predict_cnn`, `hybrid_predict`, `compute_multimode_metrics`.
   - Never passes test set as validation data.
   - Output: Evaluates separate RF, CNN, and Hybrid performance on test set.

4. **`06_Universal_Schema_Mapper.ipynb`**:
   - Unpacks `(X_encoded, y_binary, info)` adapter outputs across all 3 domains.
   - Enforces `ip_bytes_policy="exclude"` for BoT-IoT.
   - Verifies 28 features, exact column ordering, and schema version `28f-v2`.

5. **`07_Cross_Validation_BoT_IoT.ipynb`**:
   - Trains source Random Forest on ToN-IoT (`1000` flows).
   - Applies frozen pipeline to target BoT-IoT dataset (`1000` flows, `{0: 477, 1: 523}`).
   - Restores cross-domain evaluation: computes and displays transfer confusion matrix, accuracy, precision, recall, and F1.

6. **`10_Omni_Model_Training.ipynb`**:
   - Calls `run_train_omni(args)` with bounded parameters.
   - Evaluates multi-domain combined performance and domain slices (ToN-IoT, BoT-IoT, CIC-IDS2017).
   - Produces and validates candidate package with manifest.

---

## 5. Environment & Resource Status

- **Host OS**: Windows (Shell: PowerShell)
- **Python Version**: `3.14.0`
- **TensorFlow**: **NOT INSTALLED** (Full training is strictly blocked until installed)
- **Available RAM**: `1.06 GB` (Total: `13.83 GB`)
- **Free Disk Space**: `2.15 GB` (Total: `474.72 GB`)
- **GPU**: None detected in active Python environment.
- **Hardware SQLite Database (`data/sentrix.db`)**: 143 real hardware sensor records verified intact.

---

## 6. Prompt 2 Handoff & Restrictions

- **Decision**: **Prompt 2 remains ON HOLD**.
- **Prerequisites for Prompt 2**:
  1. Prepare a high-memory/CPU or GPU-capable environment (e.g. WSL2 Linux environment with TensorFlow >= 2.15 installed, >= 8 GB free RAM, and >= 20 GB free disk space for artifacts).
  2. Full retraining, candidate activation, and physical attack trials must remain separate, user-authorized milestones.
  3. No changes to the active deployment or `data/sentrix.db` are authorized.
