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
    encode_dataframe,
    EncodingError,
    parse_binary_flag,
)
from sentrix_ml.packaging import (
    ModelManifest,
    validate_package,
    PackageValidationError,
    create_package,
    file_sha256,
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
from sentrix_ml.splits import SplitManifest
from sentrix_ml.adapters.ton_iot import load_ton_iot
from sentrix_ml.adapters.bot_iot import load_bot_iot
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


# =====================================================================
# Follow-up Review Item 2: Preflight & Raw Data Acceptance Checks
# =====================================================================

def test_item2_adapters_reject_label_only_csv():
    """Verify adapters reject raw CSVs that contain only labels without traffic features."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. ToN-IoT label-only
        ton_csv = Path(tmpdir) / "ton_label_only.csv"
        ton_csv.write_text("label\n0\n1\n0\n")
        with pytest.raises(ValueError, match="missing mandatory traffic columns"):
            load_ton_iot(ton_csv)

        # 2. BoT-IoT label-only
        bot_csv = Path(tmpdir) / "bot_label_only.csv"
        bot_csv.write_text("category,subcategory,attack\nNormal,Normal,0\nDDoS,TCP,1\n")
        with pytest.raises(ValueError, match="missing mandatory traffic columns"):
            load_bot_iot(bot_csv)

        # 3. CIC-IDS2017 label-only
        cic_csv = Path(tmpdir) / "cic_label_only.csv"
        cic_csv.write_text(" Label\nBENIGN\nDoS\n")
        with pytest.raises(ValueError, match="missing mandatory traffic columns"):
            load_cic_ids2017(cic_csv)


def test_item2_chunked_sampling_covers_both_classes_on_ordered_file():
    """Verify chunked sampling from ordered file (500 benign followed by 500 attack) yields both classes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "ordered_ton.csv"
        header = "ts,src_ip,src_port,dst_ip,dst_port,proto,conn_state,duration,src_bytes,dst_bytes,missed_bytes,src_pkts,src_ip_bytes,dst_pkts,dst_ip_bytes,dns_query,dns_qclass,dns_qtype,dns_rcode,http_trans_depth,http_method,http_uri,http_version,http_request_body_len,http_response_body_len,http_status_code,type,label\n"
        benign_row = "1000,192.168.1.1,1234,10.0.0.1,80,tcp,SF,1.0,500,1000,0,5,500,5,1000,-,-,-,-,-,-,-,-,-,-,-,normal,0\n"
        attack_row = "2000,192.168.1.2,1235,10.0.0.1,80,tcp,SF,1.0,500,1000,0,5,500,5,1000,-,-,-,-,-,-,-,-,-,-,-,attack,1\n"
        lines = [header] + [benign_row] * 500 + [attack_row] * 500
        csv_path.write_text("".join(lines))

        X, y, info = load_ton_iot(csv_path, sample_n=50, seed=42)
        assert len(y) == 50
        counts = pd.Series(y).value_counts()
        assert 0 in counts and 1 in counts, f"Sampling failed to capture both classes: {counts}"
        assert counts[0] >= 10 and counts[1] >= 10, f"Expected balanced sampling, got {counts}"


def test_item2_preflight_fails_on_single_class_data():
    """Verify preflight readiness check marks dataset as not ready when single class is present."""
    from sentrix_ml.preflight import check_ton_iot
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "Network_dataset_1.csv"
        header = "ts,src_ip,src_port,dst_ip,dst_port,proto,conn_state,duration,src_bytes,dst_bytes,missed_bytes,src_pkts,src_ip_bytes,dst_pkts,dst_ip_bytes,dns_query,dns_qclass,dns_qtype,dns_rcode,http_trans_depth,http_method,http_uri,http_version,http_request_body_len,http_response_body_len,http_status_code,type,label\n"
        benign_row = "1000,192.168.1.1,1234,10.0.0.1,80,tcp,SF,1.0,500,1000,0,5,500,5,1000,-,-,-,-,-,-,-,-,-,-,-,normal,0\n"
        lines = [header] + [benign_row] * 100
        csv_path.write_text("".join(lines))

        res = check_ton_iot(Path(tmpdir))
        assert res["status"] == "FAILED"
        assert "single-class" in res["error"].lower()


def test_item2_bot_iot_ip_bytes_policy_exclude():
    """Verify BoT-IoT adapter zeroes src_ip_bytes and dst_ip_bytes when ip_bytes_policy='exclude'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "bot_sample.csv"
        header = "pkSeqID,proto,saddr,sport,daddr,dport,dur,spkts,dpkts,sbytes,dbytes,TnBPSrcIP,TnBPDstIP,state,attack,category,subcategory\n"
        row1 = "1,tcp,192.168.1.1,1234,10.0.0.1,80,1.5,10,10,1000,2000,999999,888888,CON,0,Normal,Normal\n"
        row2 = "2,tcp,192.168.1.2,1235,10.0.0.1,80,0.5,5,5,500,1000,999999,888888,CON,1,DDoS,TCP\n"
        csv_path.write_text(header + row1 + row2)

        X_loaded, y_loaded, info = load_bot_iot(csv_path, ip_bytes_policy="exclude")
        assert len(X_loaded) == 2
        assert X_loaded["src_ip_bytes"].iloc[0] == 0.0
        assert X_loaded["dst_ip_bytes"].iloc[0] == 0.0


# =====================================================================
# Follow-up Review Item 3: Backend Strict Deployment Validation
# =====================================================================

def test_item3_backend_loader_rejects_mock_smoke_and_target_mismatch():
    """Verify backend load_models_and_data rejects mock/smoke packages in omni slot."""
    from backend import main as backend_main
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()
        cand_dir = Path(tmpdir) / "candidates" / "omni"
        cand_dir.parent.mkdir(parents=True, exist_ok=True)

        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf.joblib"
        joblib.dump(rf, rf_path)

        pipe = PreprocessingPipeline.fit(pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES))
        pipe_path = src_dir / "pipe.joblib"
        pipe.save(pipe_path)

        cnn_path = src_dir / "cnn.h5"
        cnn_path.write_bytes(b"dummy")

        create_package(
            output_dir=cand_dir,
            domain="omni",
            run_type="smoke",
            is_mock=True,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
        )

        with pytest.raises(PackageValidationError):
            backend_main.load_models_and_data(target="omni", dataset="omni", candidates_dir=str(cand_dir))


def test_item3_backend_loader_rejects_unfitted_pipeline():
    """Verify backend load_models_and_data rejects unfitted PreprocessingPipeline."""
    from backend import main as backend_main
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()
        cand_dir = Path(tmpdir) / "candidates" / "ton_iot"
        cand_dir.parent.mkdir(parents=True, exist_ok=True)

        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf.joblib"
        joblib.dump(rf, rf_path)

        pipe = PreprocessingPipeline()
        assert not pipe.is_fitted
        pipe_path = src_dir / "pipe.joblib"
        pipe.save(pipe_path)

        cnn_path = src_dir / "cnn.h5"
        cnn_path.write_bytes(b"dummy")

        split_m = SplitManifest(
            seed=42, train_indices=[0], val_indices=[1], test_indices=[2],
        )
        split_path = src_dir / "split_manifest.json"
        split_m.save(split_path)

        ev_path = src_dir / "evidence.csv"
        ev_path.write_text("y_true,p_rf,p_cnn,p_hybrid\n0,0.1,0.2,0.15\n1,0.9,0.8,0.85\n")

        eval_res = compute_multimode_metrics(
            np.array([0, 1]), p_rf=np.array([0.1, 0.9]), p_cnn=np.array([0.2, 0.8]),
            p_hybrid=np.array([0.15, 0.85]), domain="ton_iot", run_type="full",
            rf_hash=file_sha256(rf_path), cnn_hash=file_sha256(cnn_path),
            preprocessor_hash=file_sha256(pipe_path),
            split_manifest_hash=file_sha256(split_path),
            evidence_hash=file_sha256(ev_path),
        )
        eval_path = src_dir / "evaluation.json"
        eval_res.save(eval_path)

        create_package(
            output_dir=cand_dir,
            domain="ton_iot",
            run_type="full",
            is_mock=False,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            evaluation_path=eval_path,
            split_manifest_path=split_path,
            evidence_path=ev_path,
        )

        with pytest.raises(PackageValidationError, match="Preprocessing pipeline is not fitted"):
            backend_main.load_models_and_data(target="ton_iot", dataset="ton_iot", candidates_dir=str(cand_dir))


def test_item3_failed_switch_rollback_via_api():
    """Verify failed model switch rolls back state cleanly via FastAPI test client."""
    from fastapi.testclient import TestClient
    from backend import main as backend_main
    from backend import database as backend_db

    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = str(Path(tmpdir) / "test_switch.db")
        os.environ["SENTRIX_DB_PATH"] = test_db
        backend_db.init_db()

        client = TestClient(backend_main.app)

        initial_rf = RandomForestClassifier(n_estimators=5, random_state=42)
        initial_rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        initial_pipe = PreprocessingPipeline.fit(pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES))

        with backend_main.engine_lock:
            backend_main.engine.current_model = "omni"
            backend_main.engine.current_dataset = "omni"
            backend_main.engine.rf_model = initial_rf
            backend_main.engine.pipeline = initial_pipe
            backend_main.engine.scaler = initial_pipe.scaler
            backend_main.engine.execution_mode = "rf"
            backend_main.system_status["rf_online"] = True
            backend_main.system_status["cnn_online"] = False

        resp = client.post("/api/switch", json={"model_type": "cic_ids2017", "dataset": "cic_ids2017", "mode": "rf"})
        assert resp.status_code == 409
        assert "Switch not applied" in resp.json()["detail"]

        with backend_main.engine_lock:
            assert backend_main.engine.current_model == "omni"
            assert backend_main.engine.rf_model is initial_rf
            assert backend_main.engine.pipeline is initial_pipe
            assert backend_main.system_status["rf_online"] is True


# =====================================================================
# Follow-up Review Item 4: Metrics Integrity Checks
# =====================================================================

def test_item4_api_model_metrics_tampering_rejected():
    """Verify /api/model-metrics returns available=False when evaluation file on disk is modified."""
    from backend import main as backend_main
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_dir = Path(tmpdir) / "candidate"
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()

        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf.joblib"; joblib.dump(rf, rf_path)
        pipe = PreprocessingPipeline.fit(pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES))
        pipe_path = src_dir / "pipe.joblib"; pipe.save(pipe_path)
        cnn_path = src_dir / "cnn.h5"; cnn_path.write_bytes(b"dummy")

        eval_res = compute_multimode_metrics(
            np.array([0, 1]), p_rf=np.array([0.1, 0.9]), p_cnn=np.array([0.2, 0.8]),
            p_hybrid=np.array([0.15, 0.85]), domain="omni", run_type="full",
            rf_hash=file_sha256(rf_path), cnn_hash=file_sha256(cnn_path), preprocessor_hash=file_sha256(pipe_path)
        )
        eval_path = src_dir / "evaluation.json"
        eval_res.save(eval_path)

        manifest = create_package(
            output_dir=pkg_dir, domain="omni", run_type="full", is_mock=False,
            rf_path=rf_path, cnn_path=cnn_path, pipeline_path=pipe_path,
            evaluation_path=eval_path
        )

        with backend_main.engine_lock:
            backend_main.engine.manifest = manifest
            backend_main.engine.package_dir = str(pkg_dir)
            backend_main.engine.execution_mode = "rf"

        # 1. Untampered: should return available=True
        metrics_resp = backend_main.get_model_metrics()
        assert metrics_resp["available"] is True

        # 2. Tamper with evaluation file on disk (change accuracy without updating manifest hash)
        eval_content = json.loads(eval_path.read_text())
        eval_content["modes"]["rf"]["accuracy"] = 0.1234
        (pkg_dir / manifest.evaluation_file).write_text(json.dumps(eval_content))

        # 3. Tampered: must return available=False
        tampered_resp = backend_main.get_model_metrics()
        assert tampered_resp["available"] is False
        assert "tampered" in tampered_resp["reason"].lower() or "mismatch" in tampered_resp["reason"].lower()


def test_item4_metrics_missing_hashes_rejected():
    """Verify format_metrics_for_api rejects evaluation result with missing artifact hashes."""
    eval_res = compute_multimode_metrics(
        np.array([0, 1]), p_rf=np.array([0.1, 0.9]), p_cnn=np.array([0.2, 0.8]),
        p_hybrid=np.array([0.15, 0.85]), domain="omni", run_type="full",
        rf_hash=None, cnn_hash=None, preprocessor_hash=None
    )
    class FakeManifest:
        rf_hash = "sha256:123"
        cnn_hash = "sha256:456"
        preprocessor_hash = "sha256:789"
        domain = "omni"

    res = format_metrics_for_api(eval_res, mode="rf", active_manifest=FakeManifest())
    assert res["available"] is False
    assert "missing" in res["reason"].lower()


# =====================================================================
# Follow-up Review Item 5: Canonical Encoding Equivalence & Contradictions
# =====================================================================

def test_item5_negative_numerics_rejected_by_both_encoders():
    """Verify build_feature_row and encode_dataframe both reject negative numeric features."""
    neg_row = {"src_bytes": -1}
    with pytest.raises(EncodingError, match="Negative value not permitted"):
        build_feature_row(neg_row)

    neg_df = pd.DataFrame([neg_row])
    with pytest.raises(EncodingError, match="Negative value not permitted"):
        encode_dataframe(neg_df)


def test_item5_none_proto_with_one_hot_accepted_by_both():
    """Verify proto=None with proto_tcp=1 is accepted identically by build_feature_row and encode_dataframe."""
    row = {"proto": None, "proto_tcp": 1, "src_bytes": 100}
    row_df = build_feature_row(row)
    assert row_df.at[0, "proto_tcp"] == 1.0

    batch_df = encode_dataframe(pd.DataFrame([row]))
    assert batch_df.at[0, "proto_tcp"] == 1.0
    assert np.allclose(row_df.values, batch_df.values)


def test_item5_comprehensive_batch_vs_single_row_equivalence():
    """Verify batch encode_dataframe agrees with row-by-row build_feature_row across 10 diverse rows."""
    test_rows = [
        {"duration": 1.0, "src_bytes": 100, "dst_bytes": 200, "proto": "tcp", "conn_state": "SF"},
        {"duration": 0.5, "src_bytes": 50, "dst_bytes": 0, "proto": "udp", "conn_state": "S0"},
        {"duration": 0.0, "src_bytes": 0, "dst_bytes": 0, "proto": "icmp", "conn_state": "OTH"},
        {"duration": 2.0, "src_bytes": 1500, "dst_bytes": 3000, "proto_tcp": 1, "conn_state_SF": 1},
        {"duration": 0.1, "src_bytes": 80, "dst_bytes": 160, "proto": None, "proto_udp": 1},
        {"duration": 3.0, "src_bytes": 400, "dst_bytes": 800, "conn_state": None, "conn_state_REJ": 1},
        {"duration": 0.05, "src_bytes": 20, "dst_bytes": 40, "proto": "other", "conn_state": "other"},
        {"duration": 1.2, "src_bytes": 250, "dst_bytes": 500, "dns_query": 0, "http_status_code": 0},
        {"duration": 0.8, "src_bytes": 300, "dst_bytes": 600, "proto": "tcp", "conn_state": "RSTO"},
        {"duration": 5.0, "src_bytes": 10000, "dst_bytes": 20000, "proto": "tcp", "conn_state": "SF"},
    ]
    batch_input = pd.DataFrame(test_rows)
    batch_encoded = encode_dataframe(batch_input)

    single_encoded_list = [build_feature_row(r) for r in test_rows]
    single_encoded = pd.concat(single_encoded_list, ignore_index=True)

    assert list(batch_encoded.columns) == EXPECTED_FEATURES
    assert list(single_encoded.columns) == EXPECTED_FEATURES
    assert np.allclose(batch_encoded.values, single_encoded.values, equal_nan=True)


# =====================================================================
# Follow-up Review Item 7: XAI Provenance Strictness
# =====================================================================

def test_item7_shap_without_hash_rejected_for_hashed_active_model():
    """Verify stored SHAP without model hash is rejected when active model has a durable hash."""
    prov_no_hash = XAIProvenance(
        model_domain="ton_iot",
        representation="scaled",
        model_hash=None,
    )
    dummy_row = np.zeros(NUM_FEATURES)
    dummy_sample = pd.DataFrame(np.zeros((5, NUM_FEATURES)), columns=EXPECTED_FEATURES)
    dummy_shap = np.ones((5, NUM_FEATURES)) * 0.5

    res = reference_shap_explanation(
        dummy_row,
        X_sample=dummy_sample,
        shap_values=dummy_shap,
        provenance=prov_no_hash,
        active_domain="ton_iot",
        active_model_hash="sha256:active_model_hash_9999",
    )
    assert res.method != "reference_sample_shap"
    assert "provenance check" in res.reason.lower() or "unavailable" in res.reason.lower()


# =====================================================================
# Follow-up Review Item 8: Adaptation Source Provenance
# =====================================================================

def test_item8_adaptation_source_provenance_enforced():
    """Verify train_adaptation rejects non-ton_iot source packages and verifies source manifest."""
    from sentrix_ml.train_adaptation import run_train_adaptation
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "source_candidate"
        src_dir.mkdir()
        rf = RandomForestClassifier(n_estimators=5, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), np.array([0, 1] * 5))
        rf_path = src_dir / "rf.joblib"; joblib.dump(rf, rf_path)
        pipe = PreprocessingPipeline.fit(pd.DataFrame(np.zeros((10, NUM_FEATURES)), columns=EXPECTED_FEATURES))
        pipe_path = src_dir / "pipe.joblib"; pipe.save(pipe_path)
        cnn_path = src_dir / "cnn.h5"; cnn_path.write_bytes(b"dummy")

        create_package(
            output_dir=src_dir,
            domain="cic_ids2017",
            run_type="smoke",
            is_mock=True,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
        )

        with pytest.raises(ValueError, match="Source candidate domain must be 'ton_iot'"):
            run_train_adaptation([
                "--domain", "bot_iot",
                "--source-candidate", str(src_dir),
                "--data-dir", str(tmpdir),
                "--output-dir", str(Path(tmpdir) / "adapt_out"),
                "--run-type", "smoke",
            ])


if __name__ == "__main__":
    pytest.main(["-v", __file__])

