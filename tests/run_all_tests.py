"""Standalone test runner for SENTRi-X T1-T11 test suite.

Can be run directly via:
    python tests/run_all_tests.py
Does not require pytest to be pre-installed.
"""

import sys
import time
import traceback
from pathlib import Path

# Add project root and backend to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "backend"))

import tests


def run_suite():
    tests = [
        ("T1: Split Isolation", "tests.test_t1_splits", [
            "test_t1_stratified_split_disjoint",
            "test_t1_held_out_leakage_isolation",
            "test_t1_adaptation_split_disjoint",
            "test_t1_clean_labels_nan_rejection",
        ]),
        ("T2: Encoding & Alignment", "tests.test_t2_encoding", [
            "test_t2_text_vs_onehot_equivalence",
            "test_t2_udp_and_state_encoding",
            "test_t2_unknown_categories",
            "test_t2_missing_numeric_coercion",
            "test_t2_dataframe_encoding",
        ]),
        ("T3: Training / Live Equivalence", "tests.test_t3_equivalence", [
            "test_t3_offline_and_live_transform_equivalence",
            "test_t3_pipeline_serialization_roundtrip",
        ]),
        ("T4: Transformation Coverage", "tests.test_t4_transforms", [
            "test_t4_input_order_invariance",
            "test_t4_single_scaling_policy",
            "test_t4_unfitted_pipeline_raises",
            "test_t4_shape_validation",
        ]),
        ("T5: Hybrid Regression (Broadcast Fix)", "tests.test_t5_hybrid_regression", [
            "test_t5_hybrid_broadcast_regression",
            "test_t5_rf_and_cnn_standalone_modes",
            "test_t5_invalid_probability_rejection",
        ]),
        ("T6: Classification Boundaries & Alert Gate", "tests.test_t6_boundaries", [
            "test_t6_exact_half_boundary_is_attack",
            "test_t6_just_below_boundary_is_benign",
            "test_t6_alert_threshold_gate",
        ]),
        ("T7: Artifact Packaging & Hash Validation", "tests.test_t7_packaging", [
            "test_t7_valid_package_passes",
            "test_t7_corrupted_hash_rejected",
            "test_t7_missing_file_rejected",
            "test_t7_feature_schema_mismatch_rejected",
            "test_t7_cnn_shape_mismatch_rejected",
        ]),
        ("T8: Prediction Parity", "tests.test_t8_parity", [
            "test_t8_offline_backend_parity_all_modes",
        ]),
        ("T9: Metrics Provenance", "tests.test_t9_metrics", [
            "test_t9_metrics_computation",
            "test_t9_smoke_run_is_unavailable_in_api",
            "test_t9_full_run_is_available",
            "test_t9_single_class_auc_is_none",
        ]),
        ("T10: XAI Consistency & Provenance", "tests.test_t10_xai", [
            "test_t10_mismatched_domain_rejected",
            "test_t10_matching_domain_accepted",
            "test_t10_missing_artifacts_honest_unavailable",
        ]),
        ("T11: Existing Behavior Regression", "tests.test_t11_existing_behavior", [
            "test_t11_attack_injection_rejected",
            "test_t11_simulation_disabled_in_status",
            "test_t11_heartbeat_updates_liveness",
            "test_t11_settings_persistence",
        ]),
        ("T12: Prompt 1 Review Regression Checks", "tests.test_prompt1_review_fixes", [
            "test_item1_full_training_requires_tf_and_fails_safely",
            "test_item1_mock_artifacts_cannot_pass_deployment_validation",
            "test_item2_preflight_nonzero_on_missing_tf_when_required",
            "test_item2_adapters_reject_label_only_csv",
            "test_item2_chunked_sampling_covers_both_classes_on_ordered_file",
            "test_item2_preflight_fails_on_single_class_data",
            "test_item2_bot_iot_ip_bytes_policy_exclude",
            "test_item3_package_validation_rejects_wrong_schema_and_classes",
            "test_item3_package_validation_rejects_target_slot_mismatch",
            "test_item3_backend_loader_rejects_mock_smoke_and_target_mismatch",
            "test_item3_backend_loader_rejects_unfitted_pipeline",
            "test_item3_failed_switch_rollback_via_api",
            "test_item4_parse_binary_flag_string_zero_is_false",
            "test_item4_contradictory_representations_rejected",
            "test_item4_canonical_encoding_agreement_across_types",
            "test_item4_pure_one_hot_series_retains_flags",
            "test_item4_api_model_metrics_tampering_rejected",
            "test_item4_metrics_missing_hashes_rejected",
            "test_item5_multimode_metrics_and_prediction_evidence",
            "test_item5_api_rejects_hash_tampering",
            "test_item5_negative_numerics_rejected_by_both_encoders",
            "test_item5_none_proto_with_one_hot_accepted_by_both",
            "test_item5_comprehensive_batch_vs_single_row_equivalence",
            "test_item6_ton_iot_imputes_optional_dns_http_without_dropping_rows",
            "test_item6_cic_ids2017_converts_microseconds_to_seconds",
            "test_item7_reference_shap_rejects_cross_domain",
            "test_item7_shap_without_hash_rejected_for_hashed_active_model",
            "test_item8_adaptation_source_provenance_enforced",
        ]),
        ("T13: Rewritten Notebook Executions", "tests.test_notebook_executions", [
            "test_notebook_01_etl_ton_iot",
            "test_notebook_03_cnn_ton_iot",
            "test_notebook_04_hybrid_fusion_ton_iot",
            "test_notebook_06_universal_schema_mapper",
            "test_notebook_07_cross_validation_bot_iot",
            "test_notebook_10_omni_training",
        ]),
    ]

    print("=" * 70)
    print("       SENTRi-X ML Pipeline Corrections — Test Suite (T1-T13)")
    print("=" * 70)

    total_passed = 0
    total_failed = 0
    results_table = []
    start_time = time.time()

    for category, module_name, test_fns in tests:
        mod = __import__(module_name, fromlist=test_fns)
        cat_passed = 0
        cat_failed = 0

        # Special setup for fixtures if needed
        fixture_obj = None
        if module_name == "tests.test_t7_packaging":
            import tempfile, joblib, numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sentrix_ml.schema import NUM_FEATURES
            from sentrix_ml.preprocessing import PreprocessingPipeline
            from sentrix_ml.packaging import create_package
            tmp = Path(tempfile.mkdtemp())
            rf = RandomForestClassifier(n_estimators=2, random_state=42)
            rf.fit(np.zeros((10, NUM_FEATURES)), [0] * 5 + [1] * 5)
            rf_p = tmp / "src_rf.joblib"; joblib.dump(rf, rf_p)
            cnn_p = tmp / "src_cnn.h5"; cnn_p.write_bytes(b"dummy_cnn_content")
            pipe = PreprocessingPipeline().fit(np.zeros((10, NUM_FEATURES)))
            pipe_p = tmp / "src_pipe.joblib"; pipe.save(pipe_p)
            pkg_p = tmp / "candidate"
            create_package(pkg_p, domain="omni", rf_path=rf_p, cnn_path=cnn_p, pipeline_path=pipe_p)
            fixture_obj = pkg_p

        elif module_name == "tests.test_t11_existing_behavior":
            import tempfile, os
            from unittest.mock import patch
            from fastapi.testclient import TestClient
            import database, main
            tmp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(tmp_dir, "test_sentrix.db")
            patcher = patch("database.DB_PATH", temp_db)
            patcher.start()
            database.init_db()
            client = TestClient(main.app)
            fixture_obj = (client, main)

        for fn_name in test_fns:
            fn = getattr(mod, fn_name)
            try:
                if fixture_obj is not None:
                    # For T7, make a copy of the fixture dir so tests don't corrupt each other
                    if module_name == "tests.test_t7_packaging":
                        import shutil, tempfile
                        test_pkg = Path(tempfile.mkdtemp()) / "test_pkg"
                        shutil.copytree(fixture_obj, test_pkg)
                        fn(test_pkg)
                        shutil.rmtree(test_pkg.parent, ignore_errors=True)
                    else:
                        fn(fixture_obj)
                else:
                    fn()
                cat_passed += 1
                total_passed += 1
            except Exception as e:
                cat_failed += 1
                total_failed += 1
                print(f"\n[FAIL] {category} -> {fn_name}:")
                traceback.print_exc()

        status_str = "PASS" if cat_failed == 0 else "FAIL"
        results_table.append((category, len(test_fns), cat_passed, cat_failed, status_str))

    elapsed = time.time() - start_time

    print("\n" + "-" * 70)
    print(f"{'Category':<45} | {'Total':<5} | {'Pass':<5} | {'Fail':<5} | Status")
    print("-" * 70)
    for cat, tot, p, f, st in results_table:
        print(f"{cat:<45} | {tot:<5} | {p:<5} | {f:<5} | {st}")
    print("-" * 70)
    print(f"Total Tests: {total_passed + total_failed} | Passed: {total_passed} | Failed: {total_failed} | Time: {elapsed:.2f}s")
    print("=" * 70)

    if total_failed > 0:
        sys.exit(1)
    else:
        print("ALL TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)


if __name__ == "__main__":
    run_suite()
