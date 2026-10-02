"""Real serialization and HTTP parity on synthetic fixtures, never research metrics."""
import json
from pathlib import Path
import sys
import joblib
import numpy as np
import pytest
from tests.synthetic_data import write_datasets


def test_real_saved_models_match_backend_in_all_modes(tmp_path, monkeypatch):
    tf = pytest.importorskip("tensorflow", reason="Real CNN parity requires TensorFlow; mock fallback is forbidden")
    from fastapi.testclient import TestClient
    from sentrix_ml.train_source import run_train_source
    from sentrix_ml.train_adaptation import run_train_adaptation
    from sentrix_ml.train_omni import run_train_omni
    from sentrix_ml.preprocessing import PreprocessingPipeline, build_feature_row
    from sentrix_ml.inference import run_single_inference
    from sentrix_ml.packaging import validate_package, file_sha256
    from sentrix_ml.preflight import run_preflight

    raw_root = write_datasets(tmp_path / "raw", n=200)
    # Actual configured preflight (all four runs), using precisely these sample limits.
    assert run_preflight(["--require-tf", "--data-root", str(raw_root),
        "--sample-n", "200", "--sample-per-domain", "200"]) == 0
    packages = {}
    common = ["--run-type", "full", "--rf-estimators", "3", "--cnn-epochs", "1", "--batch-size", "32"]
    packages["ton_iot"] = tmp_path / "source_candidate"
    run_train_source(["--data-dir", str(raw_root / "ton_iot"), "--sample-n", "200",
                      "--output-dir", str(packages["ton_iot"]), *common])
    for domain in ("bot_iot", "cic_ids2017"):
        packages[domain] = tmp_path / (domain + "_candidate")
        run_train_adaptation(["--domain", domain, "--data-dir", str(raw_root / domain),
            "--sample-n", "200", "--source-candidate", str(packages["ton_iot"]),
            "--output-dir", str(packages[domain]), *common])
    packages["omni"] = tmp_path / "omni_candidate"
    run_train_omni(["--data-root", str(raw_root), "--sample-per-domain", "200",
                   "--output-dir", str(packages["omni"]), *common])

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
    import database
    from backend import main
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "parity.sqlite"))
    database.init_db()
    monkeypatch.setattr(main, "engine", main.ActiveEngine())
    monkeypatch.setattr(main, "system_status", dict(main.system_status))
    monkeypatch.setattr(main, "settings", {"active_alerting": False, "alert_threshold": .87})
    client = TestClient(main.app)
    payload = {"src_ip": "192.168.1.2", "dst_ip": "192.168.1.3", "sensor_id": "isolated-test",
               "duration": 1.25, "src_bytes": 150, "dst_bytes": 60, "src_pkts": 3, "dst_pkts": 2,
               "src_ip_bytes": 230, "dst_ip_bytes": 140, "proto": "tcp", "conn_state": "SF"}
    for domain, package in packages.items():
        manifest = validate_package(package, strict_deployable=True, target_domain=domain)
        assert not manifest.is_mock
        offline_pipe = PreprocessingPipeline.load(package / manifest.preprocessor_file)
        offline_rf = joblib.load(package / manifest.rf_file)
        offline_cnn = tf.keras.models.load_model(package / manifest.cnn_file, compile=False)
        canonical = build_feature_row(payload)
        offline_scaled = offline_pipe.transform(canonical)
        main.load_models_and_data(domain, domain, candidates_dir=str(package))
        np.testing.assert_allclose(main.engine.pipeline.transform(main.prepare_feature_dataframe(payload)),
                                   offline_scaled, atol=1e-12, rtol=0)
        assert main.engine.manifest.rf_hash == file_sha256(package / manifest.rf_file)
        assert main.engine.manifest.cnn_hash == file_sha256(package / manifest.cnn_file)
        assert main.engine.manifest.preprocessor_hash == file_sha256(package / manifest.preprocessor_file)
        split = json.loads((package / manifest.split_manifest_file).read_text())
        assert split["sampling_metadata"] and split["train_records"] and split["val_records"] and split["test_records"]
        for mode in ("rf", "cnn", "hybrid"):
            expected = run_single_inference(offline_scaled, rf_model=offline_rf, cnn_model=offline_cnn, mode=mode)
            switch = client.post("/api/switch", json={"model_type": domain, "dataset": domain, "mode": mode})
            assert switch.status_code == 200, switch.text
            response = client.post("/api/ingest-flow", json=payload)
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["prediction"] == expected.prediction
            assert result["confidence"] == pytest.approx(expected.confidence, abs=1e-6)
            for key in ("p_rf", "p_cnn"):
                actual = result[key]; wanted = getattr(expected, key)
                assert actual is None if wanted is None else actual == pytest.approx(wanted, abs=1e-6)
        # Round-trip saved ToN IDs to their raw rows, not merely nonempty strings.
        if domain == "ton_iot":
            source = __import__("pandas").read_csv(raw_root / "ton_iot" / "Network_dataset_1.csv")
            for record in split["train_records"] + split["val_records"] + split["test_records"]:
                assert 0 <= record["source_row_index"] < len(source)
                assert record["source_file_hash"] == file_sha256(raw_root / "ton_iot" / record["source_file"])
    assert len(client.get("/api/flows", params={"limit": 100}).json()["flows"]) == 12
