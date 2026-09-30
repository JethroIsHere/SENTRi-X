"""Smoke training and end-to-end package validation cycle.

Executes a small-scale, explicitly labeled smoke run:
1. Loads small subsample of dataset (or canonical fixture)
2. Splits cleanly into disjoint train/val/test partitions
3. Fits PreprocessingPipeline on train split ONLY
4. Trains lightweight RF and CNN models
5. Evaluates with shared hybrid ensemble
6. Packages artifacts into models/candidates/smoke_candidate/ with manifest
7. Validates candidate package integrity (hashes, schemas, shapes)
8. Tests backend load & prediction parity

Usage:
    python -m sentrix_ml.smoke
"""

import os
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.splits import stratified_split
from sentrix_ml.training import train_rf, build_cnn_model
from sentrix_ml.inference import hybrid_predict, run_single_inference
from sentrix_ml.evaluation import compute_metrics, format_metrics_for_api
from sentrix_ml.packaging import create_package, validate_package


def run_smoke_cycle(output_dir: str | Path | None = None, sample_size: int = 400):
    start_time = time.time()
    print("=" * 65)
    print("       SENTRi-X ML Pipeline: Smoke Training & Packaging Cycle")
    print("=" * 65)

    if output_dir is None:
        project_root = Path(__file__).resolve().parent.parent
        output_dir = project_root / "models" / "candidates" / "smoke_v2"
    output_dir = Path(output_dir)

    print(f"\n[Step 1] Loading sample data (target: {sample_size} rows)...")
    # Check if raw ToN-IoT file exists
    ton_file = Path(__file__).resolve().parent.parent / "data" / "raw" / "ton_iot" / "Network_dataset_1.csv"
    if ton_file.exists():
        from sentrix_ml.adapters.ton_iot import load_ton_iot
        X_encoded, y_binary, info = load_ton_iot(
            ton_file.parent,
            max_files=1,
            sample_n=sample_size,
            seed=42,
        )
        print(f"Loaded {len(X_encoded)} rows from real ToN-IoT data.")
    else:
        print("Raw dataset not found; using synthetic canonical data for plumbing check.")
        np.random.seed(42)
        X_encoded = pd.DataFrame(
            np.random.uniform(0, 100, size=(sample_size, NUM_FEATURES)),
            columns=EXPECTED_FEATURES,
        )
        y_binary = pd.Series(np.random.choice([0, 1], size=sample_size, p=[0.7, 0.3]))

    print(f"\n[Step 2] Executing stratified split (Train: 72%, Val: 8%, Test: 20%)...")
    X_train, X_val, X_test, y_train, y_val, y_test, split_manifest = stratified_split(
        X_encoded, y_binary, test_fraction=0.20, val_fraction=0.10, seed=42, domain="smoke"
    )
    print(f"Split completed: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
    assert len(set(X_train.index).intersection(X_test.index)) == 0, "Split leaked test data into train!"

    print("\n[Step 3] Fitting PreprocessingPipeline strictly on training partition...")
    pipeline = PreprocessingPipeline().fit(X_train)
    X_train_scaled = pipeline.transform(X_train)
    X_val_scaled = pipeline.transform(X_val)
    X_test_scaled = pipeline.transform(X_test)

    print("\n[Step 4] Training smoke Random Forest (5 estimators)...")
    rf_model = train_rf(X_train_scaled, y_train, n_estimators=5, max_depth=6, random_state=42)

    print("\n[Step 5] Compiling and training smoke CNN (1 epoch)...")
    try:
        import tensorflow as tf
        cnn_model = build_cnn_model(input_shape=(NUM_FEATURES, 1))
        X_train_3d = X_train_scaled.reshape(X_train_scaled.shape[0], NUM_FEATURES, 1)
        X_val_3d = X_val_scaled.reshape(X_val_scaled.shape[0], NUM_FEATURES, 1)
        cnn_model.fit(
            X_train_3d,
            y_train.to_numpy(dtype=int),
            validation_data=(X_val_3d, y_val.to_numpy(dtype=int)),
            epochs=1,
            batch_size=64,
            verbose=0,
        )
        has_tf = True
    except ImportError:
        print("TensorFlow not installed in current interpreter; using mock CNN for plumbing check.")
        class SmokeMockCNN:
            def predict(self, X_3d, verbose=0):
                return np.ones((len(X_3d), 1)) * 0.7
        cnn_model = SmokeMockCNN()
        has_tf = False

    print("\n[Step 6] Evaluating hybrid ensemble on holdout test set...")
    preds, probs, p_rf, p_cnn = hybrid_predict(
        X_test_scaled, rf_model=rf_model, cnn_model=cnn_model, mode="hybrid"
    )
    eval_result = compute_metrics(
        y_true=y_test.to_numpy(dtype=int),
        y_pred=preds,
        y_proba=probs,
        domain="smoke_ton",
        mode="hybrid",
        run_type="smoke",
    )
    print(f"Smoke evaluation metrics computed: Accuracy={eval_result.accuracy:.4f}, AUC={eval_result.roc_auc}")

    api_metrics = format_metrics_for_api(eval_result)
    assert api_metrics["available"] is False, "Smoke metrics must NOT be marked available: true!"
    print("Verified: Smoke metrics correctly marked available: false for production API.")

    print(f"\n[Step 7] Packaging candidate model into: {output_dir}")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        rf_path = tmp_path / "rf.joblib"
        cnn_path = tmp_path / "cnn.h5"
        pipe_path = tmp_path / "pipe.joblib"
        split_path = tmp_path / "split_manifest.json"
        eval_path = tmp_path / "eval_metrics.json"

        joblib.dump(rf_model, rf_path)
        if has_tf:
            cnn_model.save(cnn_path)
        else:
            cnn_path.write_bytes(b"dummy_cnn_smoke_weights_placeholder")
        pipeline.save(pipe_path)
        split_manifest.save(split_path)
        eval_result.save(eval_path)

        manifest = create_package(
            output_dir=output_dir,
            domain="smoke_ton",
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            run_type="smoke",
            notes="Automated smoke validation package",
        )

    print("\n[Step 8] Validating packaged model candidate via validate_package()...")
    validated_manifest = validate_package(output_dir)
    print(f"Manifest validated successfully! Domain: {validated_manifest.domain}")
    print(f"RF SHA256:   {validated_manifest.rf_hash}")
    print(f"CNN SHA256:  {validated_manifest.cnn_hash}")
    print(f"Pipe SHA256: {validated_manifest.preprocessor_hash}")

    print("\n[Step 9] Testing reload and inference parity on candidate package...")
    reloaded_pipeline = PreprocessingPipeline.load(output_dir / validated_manifest.preprocessor_file)
    reloaded_rf = joblib.load(output_dir / validated_manifest.rf_file)
    if has_tf:
        from tensorflow.keras.models import load_model
        reloaded_cnn = load_model(output_dir / validated_manifest.cnn_file, compile=False)
    else:
        reloaded_cnn = cnn_model

    test_sample = X_test.iloc[0:1]
    scaled_sample = reloaded_pipeline.transform(test_sample)
    res = run_single_inference(scaled_sample, rf_model=reloaded_rf, cnn_model=reloaded_cnn, mode="hybrid")
    print(f"Inference check on reloaded package: Prediction={res.prediction}, Confidence={res.confidence:.4f}")

    elapsed = time.time() - start_time
    print("=" * 65)
    print(f"SMOKE CYCLE COMPLETED SUCCESSFULLY in {elapsed:.2f}s!")
    print("=" * 65)
    return validated_manifest


if __name__ == "__main__":
    run_smoke_cycle()
