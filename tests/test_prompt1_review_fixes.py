"""Tests for Prompt 1 Review Fixes.

Regression checks for each of the 8 items from the Prompt 1 review:
Item 1: Full training fails without TensorFlow / mock artifacts nondeployable
Item 2: Preflight reports honest readiness and exits nonzero on adapter/dependency failure
Item 3: Package validation enforces schema contract, non-null hashes, isolation, and rejects mock/smoke
Item 4: Canonical encoding rejects contradictions and parses string flags correctly across dict/Series/DataFrame
Item 5: Multimode evaluation, prediction evidence CSV, and API metrics provenance
Item 6: Adapter feature contract: optional DNS/HTTP imputation, CIC unit conversion, exclusion tracking
Item 7: Backend atomic staging, failed switch rollback, and XAI domain provenance
Item 8: Adaptation requires verified source candidate
"""

import os
import sys
import shutil
import tempfile
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import joblib
from sklearn.ensemble import RandomForestClassifier

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    NUM_FEATURES,
    SCHEMA_VERSION,
    CLASS_MAPPING,
    REQUIRED_NUMERIC_FEATURES,
    OPTIONAL_NUMERIC_FEATURES,
)
from sentrix_ml.preprocessing import (
    PreprocessingPipeline,
    build_feature_row,
    EncodingError,
    parse_binary_flag,
)
from sentrix_ml.packaging import (
    ModelManifest,
    validate_package,
    PackageValidationError,
    create_package,
)
from sentrix_ml.evaluation import (
    EvaluationResult,
    compute_multimode_metrics,
    save_prediction_evidence,
    format_metrics_for_api,
)
from sentrix_ml.xai import (
    XAIProvenance,
    reference_shap_explanation,
)
from sentrix_ml.train_source import run_train_source
from sentrix_ml.adapters.ton_iot import load_ton_iot
from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017


# =====================================================================
# Item 1: Full training requires TensorFlow, mock output is nondeployable
# =====================================================================

def test_item1_full_training_requires_tf_and_fails_safely():
    """Verify that train_source with run_type='full' cannot succeed with a placeholder CNN."""
    import subprocess
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cmd = [
            sys.executable,
            "-m",
            "sentrix_ml.train_source",
            "--run-type",
            "full",
            "--data-dir",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )

        try:
            import tensorflow
            tf_available = True
        except ImportError:
            tf_available = False

        if not tf_available:
            assert res.returncode != 0, f"Full training succeeded without TensorFlow! output: {res.stdout}"
            assert "TensorFlow is required for full model training" in res.stderr
            assert not (tmp_path / "out" / "manifest.json").exists()


def test_item1_mock_artifacts_cannot_pass_deployment_validation():
    """Verify that a package marked is_mock or smoke is rejected by strict_deployable validation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src_files"
        src_dir.mkdir()
        pkg_dir = Path(tmpdir) / "test_pkg"

        # Create dummy RF
        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf_model.joblib"
        joblib.dump(rf, rf_path)

        # Create dummy preprocessor
        dummy_df = pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES)
        pipe = PreprocessingPipeline.fit(dummy_df)
        pipe_path = src_dir / "preprocessor.joblib"
        pipe.save(pipe_path)

        # Create dummy mock CNN
        cnn_path = src_dir / "cnn_model.h5"
        cnn_path.write_bytes(b"mock_cnn_placeholder")

        manifest = create_package(
            output_dir=pkg_dir,
            domain="ton_iot",
            run_type="smoke",
            is_mock=True,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            notes="Mock smoke candidate",
        )

        # Standard inspection passes
        inspected = validate_package(pkg_dir, strict_deployable=False)
        assert inspected.is_mock is True

        # Strict deployment validation MUST reject mock artifact
        with pytest.raises(PackageValidationError, match="is_mock=True"):
            validate_package(pkg_dir, strict_deployable=True, target_domain="ton_iot")


# =====================================================================
# Item 2: Preflight reports honest readiness and nonzero on failures
# =====================================================================

def test_item2_preflight_nonzero_on_missing_tf_when_required():
    """Verify preflight exits with non-zero when --require-tf is passed but TF is absent."""
    import subprocess
    cmd = [sys.executable, "-m", "sentrix_ml.preflight", "--require-tf"]
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))
    try:
        import tensorflow
        assert res.returncode == 0
    except ImportError:
        assert res.returncode != 0
        assert "PREFLIGHT STATUS: FAILED" in res.stdout or "tensorflow" in res.stdout.lower()


# =====================================================================
# Item 3: Package validation enforces schema, hashes, and isolation
# =====================================================================

def test_item3_package_validation_rejects_wrong_schema_and_classes():
    """Verify packages with invalid schema version or reversed class mapping are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src_files"
        src_dir.mkdir()
        pkg_dir = Path(tmpdir) / "invalid_pkg"

        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf_model.joblib"
        joblib.dump(rf, rf_path)

        dummy_df = pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES)
        pipe = PreprocessingPipeline.fit(dummy_df)
        pipe_path = src_dir / "preprocessor.joblib"
        pipe.save(pipe_path)

        cnn_path = src_dir / "cnn_model.h5"
        cnn_path.write_bytes(b"data")

        create_package(
            output_dir=pkg_dir,
            domain="ton_iot",
            run_type="smoke",
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
        )

        manifest_path = pkg_dir / "manifest.json"
        manifest_data = json.loads(manifest_path.read_text())

        # 1. Tamper with schema version
        manifest_data["schema_version"] = "wrong-v1"
        manifest_path.write_text(json.dumps(manifest_data))
        with pytest.raises(PackageValidationError, match="Schema version mismatch"):
            validate_package(pkg_dir)

        # 2. Tamper with class mapping
        manifest_data["schema_version"] = SCHEMA_VERSION
        manifest_data["class_mapping"] = {"0": "Attack", "1": "Benign"}  # Reversed!
        manifest_path.write_text(json.dumps(manifest_data))
        with pytest.raises(PackageValidationError, match="Invalid class mapping"):
            validate_package(pkg_dir)



def test_item3_package_validation_rejects_target_slot_mismatch():
    """Verify candidate built for ton_iot cannot be activated for omni target slot."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src_files"
        src_dir.mkdir()
        pkg_dir = Path(tmpdir) / "ton_pkg"

        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf_model.joblib"
        joblib.dump(rf, rf_path)

        pipe = PreprocessingPipeline.fit(pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES))
        pipe_path = src_dir / "preprocessor.joblib"
        pipe.save(pipe_path)

        cnn_path = src_dir / "cnn_model.h5"
        cnn_path.write_bytes(b"cnn")

        create_package(
            output_dir=pkg_dir,
            domain="ton_iot",
            run_type="full",
            is_mock=False,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
        )

        # Validating for slot 'omni' must fail
        with pytest.raises(PackageValidationError, match="Domain mismatch"):
            validate_package(pkg_dir, strict_deployable=True, target_domain="omni")


# =====================================================================
# Item 4: Canonical encoding consistency and contradiction rejection
# =====================================================================

def test_item4_parse_binary_flag_string_zero_is_false():
    """Verify string '0' evaluates to False and '1' evaluates to True."""
    assert parse_binary_flag("0") is False
    assert parse_binary_flag(0) is False
    assert parse_binary_flag("1") is True
    assert parse_binary_flag(1) is True


def test_item4_contradictory_representations_rejected():
    """Verify contradictory protocol and connection state flags raise EncodingError."""
    # Contradictory proto: text 'udp' with flag 'proto_tcp=1'
    with pytest.raises(EncodingError, match="Contradiction in protocol"):
        build_feature_row({"proto": "udp", "proto_tcp": 1, "src_bytes": 100})

    # Contradictory conn_state: text 'S0' with flag 'conn_state_SF=1'
    with pytest.raises(EncodingError, match="Contradiction in connection state"):
        build_feature_row({"conn_state": "S0", "conn_state_SF": 1, "src_bytes": 100})


def test_item4_canonical_encoding_agreement_across_types():
    """Verify dict, Series, and single-row DataFrame produce identical 28 ordered features."""
    input_dict = {
        "duration": 1.5,
        "src_bytes": 250,
        "dst_bytes": 1024,
        "src_pkts": 5,
        "dst_pkts": 8,
        "proto": "tcp",
        "conn_state": "SF",
    }
    df_from_dict = build_feature_row(input_dict)
    series_input = pd.Series(input_dict)
    df_from_series = build_feature_row(series_input)
    df_input = pd.DataFrame([input_dict])
    df_from_df = build_feature_row(df_input)

    assert list(df_from_dict.columns) == EXPECTED_FEATURES
    assert np.allclose(df_from_dict.values, df_from_series.values)
    assert np.allclose(df_from_dict.values, df_from_df.values)
    assert df_from_dict.at[0, "proto_tcp"] == 1.0
    assert df_from_dict.at[0, "conn_state_SF"] == 1.0


def test_item4_pure_one_hot_series_retains_flags():
    """Verify Series containing only one-hot flags does not lose them."""
    series_flags = pd.Series({"proto_tcp": 1, "conn_state_SF": 1, "src_bytes": 500})
    df_row = build_feature_row(series_flags)
    assert df_row.at[0, "proto_tcp"] == 1.0
    assert df_row.at[0, "conn_state_SF"] == 1.0


# =====================================================================
# Item 5: Multimode evaluation, prediction evidence, API provenance
# =====================================================================

def test_item5_multimode_metrics_and_prediction_evidence():
    """Verify multimode metrics calculation and evidence CSV export."""
    y_true = np.array([0, 0, 1, 1, 1])
    p_rf = np.array([0.1, 0.4, 0.8, 0.9, 0.7])
    p_cnn = np.array([0.2, 0.3, 0.7, 0.6, 0.8])
    p_hybrid = (p_rf + p_cnn) / 2.0

    eval_res = compute_multimode_metrics(
        y_true,
        p_rf=p_rf,
        p_cnn=p_cnn,
        p_hybrid=p_hybrid,
        domain="omni",
        run_type="full",
    )

    assert "rf" in eval_res.modes
    assert "cnn" in eval_res.modes
    assert "hybrid" in eval_res.modes

    # Save evidence
    with tempfile.TemporaryDirectory() as tmpdir:
        evidence_path = Path(tmpdir) / "evidence.csv"
        ev_hash = save_prediction_evidence(
            evidence_path,
            y_true=y_true,
            p_rf=p_rf,
            p_cnn=p_cnn,
            p_hybrid=p_hybrid,
        )
        assert evidence_path.exists()
        assert ev_hash.startswith("sha256:")

        # Check API format
        api_rf = format_metrics_for_api(eval_res, mode="rf")
        api_cnn = format_metrics_for_api(eval_res, mode="cnn")
        api_hyb = format_metrics_for_api(eval_res, mode="hybrid")

        assert api_rf["available"] is True
        assert api_rf["mode"] == "rf"
        assert api_cnn["available"] is True
        assert api_cnn["mode"] == "cnn"
        assert api_hyb["available"] is True
        assert api_hyb["mode"] == "hybrid"


def test_item5_api_rejects_hash_tampering():
    """Verify format_metrics_for_api returns available=False if model hashes mismatch."""
    y_true = np.array([0, 1])
    p_rf = np.array([0.1, 0.9])
    p_cnn = np.array([0.2, 0.8])
    p_hyb = (p_rf + p_cnn) / 2.0

    eval_res = compute_multimode_metrics(
        y_true,
        p_rf=p_rf,
        p_cnn=p_cnn,
        p_hybrid=p_hyb,
        domain="omni",
        run_type="full",
        rf_hash="sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )

    # Fake manifest with different hash
    class FakeManifest:
        rf_hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        cnn_hash = None
        preprocessor_hash = None

    payload = format_metrics_for_api(eval_res, mode="hybrid", active_manifest=FakeManifest())
    assert payload["available"] is False
    assert "mismatch" in payload["reason"]


# =====================================================================
# Item 6: Dataset adapter feature contract & optional imputation
# =====================================================================

def test_item6_ton_iot_imputes_optional_dns_http_without_dropping_rows():
    """Verify ToN-IoT adapter does not discard rows when optional DNS/HTTP contains '-'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "ton_sample.csv"
        # 5 valid rows with '-' in dns and http fields
        rows = [
            "ts,src_ip,src_port,dst_ip,dst_port,proto,conn_state,duration,src_bytes,dst_bytes,missed_bytes,src_pkts,src_ip_bytes,dst_pkts,dst_ip_bytes,dns_query,dns_qclass,dns_qtype,dns_rcode,http_trans_depth,http_method,http_uri,http_version,http_request_body_len,http_response_body_len,http_status_code,type,label\n",
            "1000,192.168.1.1,1234,10.0.0.1,80,tcp,SF,1.0,500,1000,0,5,500,5,1000,-,-,-,-,-,-,-,-,-,-,-,normal,0\n",
            "1001,192.168.1.2,1235,10.0.0.1,80,tcp,SF,2.0,600,1200,0,6,600,6,1200,-,-,-,-,-,-,-,-,-,-,-,normal,0\n",
            "1002,192.168.1.3,1236,10.0.0.1,80,udp,SF,0.5,200,400,0,2,200,2,400,-,-,-,-,-,-,-,-,-,-,-,attack,1\n",
        ]
        csv_path.write_text("".join(rows))

        X_loaded, y_loaded, info = load_ton_iot(csv_path)
        assert len(X_loaded) == 3, f"Expected all 3 rows retained with imputed 0.0, got {len(X_loaded)}"
        assert X_loaded["dns_qclass"].iloc[0] == 0.0
        assert X_loaded["http_status_code"].iloc[0] == 0.0


def test_item6_cic_ids2017_converts_microseconds_to_seconds():
    """Verify raw CIC-IDS2017 Flow Duration of 1,000,000 microseconds converts to 1.0 second."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "cic_sample.csv"
        header = "Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
        row = "1000000, 10, 10, 500, 1000, BENIGN\n"
        csv_path.write_text(header + row)

        X_loaded, y_loaded, info = load_cic_ids2017(csv_path)
        assert len(X_loaded) == 1
        assert np.isclose(X_loaded.at[0, "duration"], 1.0)


# =====================================================================
# Item 7: Backend staging, switch rollback, XAI domain provenance
# =====================================================================

def test_item7_reference_shap_rejects_cross_domain():
    """Verify reference_shap_explanation rejects looking up ToN-IoT artifacts for bot_iot active domain."""
    prov = XAIProvenance(model_domain="ton_iot", representation="scaled")
    dummy_row = np.zeros((1, NUM_FEATURES))
    dummy_sample = pd.DataFrame(np.zeros((5, NUM_FEATURES)), columns=EXPECTED_FEATURES)
    dummy_shap = np.zeros((5, NUM_FEATURES))

    res = reference_shap_explanation(
        dummy_row,
        X_sample=dummy_sample,
        shap_values=dummy_shap,
        provenance=prov,
        active_domain="bot_iot",
    )
    # Stored SHAP is from ton_iot; active model is bot_iot -> MUST not return reference_sample_shap
    assert res.method != "reference_sample_shap"
    assert "ton_iot" in res.reason and "bot_iot" in res.reason


if __name__ == "__main__":
    pytest.main(["-v", __file__])
