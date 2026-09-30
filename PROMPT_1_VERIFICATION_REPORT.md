# SENTRi-X: Prompt 1 Verification and Corrections Report

**Date**: 30 September 2026  
**Status**: All 8 Prompt 1 Review Blockers Resolved | Full Retraining HELD pending environment readiness  
**Test Suite**: 52/52 tests passed (`tests/run_all_tests.py` suites T1–T12)  
**Frontend Build**: Passed (`tsc -b && vite build`)  
**Live Hardware Database**: Preserved (143 flows in `data/sentrix.db`)  

---

## 1. Summary of Completed Fixes

| Item | Review Finding | Status | Resolution Summary | Regression Test |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Full training can succeed with a placeholder CNN | **PASSED** | Hard dependency check in `train_source.py`, `train_adaptation.py`, `train_omni.py`. When `run_type == "full"` and TensorFlow is missing, training aborts immediately with `sys.exit(1)`. `validate_package(..., strict_deployable=True)` rejects mock artifacts (`is_mock=True` or `run_type="smoke"`). | `test_item1_full_training_requires_tf_and_fails_safely`<br>`test_item1_mock_artifacts_cannot_pass_deployment_validation` |
| **2** | Preflight reports readiness when adapter checks fail | **PASSED** | Added `--target` and `--require-tf` flags to `sentrix_ml/preflight.py`. Preflight validates required dependencies, schema adherence, label validity, nonempty splits, and returns exit code `1` on any adapter failure or missing required dependency. | `test_item2_preflight_nonzero_on_missing_tf_when_required` |
| **3** | Package validation does not establish model compatibility | **PASSED** | `sentrix_ml/packaging.py` validates `schema_version == "28f-v2"`, strict binary mapping `{"0":"Benign","1":"Attack"}`, non-null sha256 hashes. `strict_deployable=True` deep-inspects fitted scaler (28 features), RF estimator (`predict_proba`, 28 features), CNN tensor shape `(None, 28, 1)`, tests inference, and prevents domain mismatch during activation. | `test_item3_package_validation_rejects_wrong_schema_and_classes`<br>`test_item3_package_validation_rejects_target_slot_mismatch` |
| **4** | Training and live encoding disagree on the same input | **PASSED** | `sentrix_ml/preprocessing.py` standardizes validation across `dict`, `pd.Series`, and `pd.DataFrame`. Strict binary parsing (`"0"` is False, `"1"` is True). Mutually exclusive contradiction detection raises `EncodingError`. Pure one-hot inputs retain flags and match text inputs. | `test_item4_parse_binary_flag_string_zero_is_false`<br>`test_item4_contradictory_representations_rejected`<br>`test_item4_canonical_encoding_agreement_across_types`<br>`test_item4_pure_one_hot_series_retains_flags` |
| **5** | Evaluation exports incomplete & API mislabels metrics | **PASSED** | `sentrix_ml/evaluation.py` calculates separate RF, CNN, and Hybrid metrics, saves per-sample prediction evidence CSV with sha256 hash, and records per-domain slice metrics for Omni. `/api/model-metrics` calls `format_metrics_for_api`, verifies artifact hashes match active manifest, matches active mode, and rejects smoke/tampered evidence. Legacy unverified metrics fallback completely removed. | `test_item5_multimode_metrics_and_prediction_evidence`<br>`test_item5_api_rejects_hash_tampering` |
| **6** | Dataset adapters violate feature contract | **PASSED** | `sentrix_ml/schema.py` divides schema into `REQUIRED_NUMERIC_FEATURES` and `OPTIONAL_NUMERIC_FEATURES`. ToN-IoT adapter imputes missing/dash optional DNS/HTTP with 0.0 without dropping rows. CIC-IDS2017 adapter converts raw microseconds to seconds (`/ 1e6`) and rejects legacy mapped CSV unless explicitly permitted. Memory-bounded ingestion prevents OOM. | `test_item6_ton_iot_imputes_optional_dns_http_without_dropping_rows`<br>`test_item6_cic_ids2017_converts_microseconds_to_seconds` |
| **7** | Backend loading and XAI bypass package contract | **PASSED** | `backend/main.py` implements atomic staging in `load_models_and_data`: staging occurs in local variables and validates inference before mutating `engine`. Automatic legacy fallback removed. `/api/switch` saves full engine state and rolls back cleanly on exception. XAI wires `reference_shap_explanation` with domain provenance; non-ToN domains return explicit unavailable status. | `test_item7_reference_shap_rejects_cross_domain` |
| **8** | Remaining Prompt 1 integration & reproducibility | **PASSED** | Updated key notebooks (`01`, `03`, `04`, `06`, `07`, `10`) to use canonical `sentrix_ml` entry points. Target adaptation requires `--source-candidate` and validates it before transfer. Added comprehensive regression suite `tests/test_prompt1_review_fixes.py` integrated into `tests/run_all_tests.py`. | T1–T12 suite (52/52 passed) |

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
  - ram_available_gb      : 0.97
  - disk_free_gb          : 2.49

[2] Raw Datasets & Schema Adapters:
  * TON_IOT: [READY]
      file_count: 23
      total_size_mb: 3216.2
      sample_file: Network_dataset_1.csv
      adapter_test: PASS (shape=(50, 28), labels={0: 50})
      exclusions: {}
  * BOT_IOT: [READY]
      file_count: 4
      total_size_mb: 970.0
      sample_file: UNSW_2018_IoT_Botnet_Full5pc_1.csv
      adapter_test: PASS (shape=(50, 28), labels={1: 50})
      exclusions: {}
      unresolved_mappings: [
        'BoT-IoT TnBPSrcIP->src_ip_bytes: per-IP aggregate vs per-flow IP bytes',
        'BoT-IoT TnBPDstIP->dst_ip_bytes: same aggregate caveat'
      ]
  * CIC_IDS2017: [READY]
      file_count: 8
      total_size_mb: 843.7
      sample_file: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
      adapter_test: PASS (shape=(50, 28), labels={0: 50})
      duration_unit: seconds
      exclusions: {}

===========================================================================
PREFLIGHT STATUS: READY FOR TRAINING (ALL)
===========================================================================
```

When executed with `--require-tf`:
```text
PREFLIGHT STATUS: FAILED — BLOCKING ISSUES DETECTED
  ! Environment dependencies missing.
Exit code: 1
```

---

## 3. Test Suite Execution Results

Command executed:
```bash
python tests/run_all_tests.py
```

Results:
```text
======================================================================
       SENTRi-X ML Pipeline Corrections — Test Suite (T1-T12)
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
T12: Prompt 1 Review Regression Checks        | 14    | 14    | 0     | PASS
----------------------------------------------------------------------
Total Tests: 52 | Passed: 52 | Failed: 0 | Time: 20.66s
======================================================================
ALL TESTS PASSED SUCCESSFULLY!
```

---

## 4. Frontend & Database State

- **Frontend Compilation**: `npm run build` executed cleanly.
  - Assets bundled: `dist/assets/index-BFwPQ0AT.js` (279.65 kB), `dist/assets/index-CP7d42Sl.css` (16.89 kB).
  - Live hardware monitoring interface intact.
- **SQLite Database Integrity**: Verified `data/sentrix.db`. All 143 live hardware records are intact. Zero modifications or truncations occurred.

---

## 5. Decision & Next Steps

1. **Prompt 1 Corrections**: Complete. All 8 findings from the code review have been addressed and verified with regression tests.
2. **Prompt 2 (Full Retraining)**: Held. Full training requires a dedicated environment with TensorFlow and sufficient RAM/GPU resources (e.g. WSL with GPU or high-memory training environment).
3. **Domain-Specific Status**:
   - `ToN-IoT`: Ready for full training once in TF environment.
   - `CIC-IDS2017`: Ready for raw data adaptation (duration unit verified as seconds).
   - `BoT-IoT`: Domain-specific aggregate mapping caveat documented; will be handled per research protocol during adaptation.
