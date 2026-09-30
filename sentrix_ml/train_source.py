"""Source model training routine for ToN-IoT dataset.

Pipeline:
1. Validates environment dependencies (TensorFlow required for full run)
2. Ingests raw ToN-IoT CSVs through canonical adapter (no leakage)
3. Stratified train/val/test split (disjoint holdout)
4. Fits PreprocessingPipeline strictly on training partition
5. Trains Random Forest on train split
6. Trains 1D CNN with explicit validation data
7. Evaluates RF, CNN, and Hybrid modes on independent holdout
8. Exports prediction-level evidence CSV
9. Assembles and validates candidate model package
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sentrix_ml.schema import NUM_FEATURES, EXPECTED_FEATURES
from sentrix_ml.adapters.ton_iot import load_ton_iot
from sentrix_ml.splits import stratified_split
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.training import train_rf, build_cnn_model, train_cnn
from sentrix_ml.evaluation import compute_multimode_metrics, save_prediction_evidence
from sentrix_ml.packaging import create_package, validate_package, file_sha256


def parse_args():
    parser = argparse.ArgumentParser(description="Train SENTRi-X Source Model on ToN-IoT")
    parser.add_argument("--data-dir", type=str, default="data/raw/ton_iot", help="Path to raw ToN-IoT CSV directory")
    parser.add_argument("--max-files", type=int, default=None, help="Maximum number of CSV files to read")
    parser.add_argument("--sample-n", type=int, default=50000, help="Bounded sample count for memory efficiency")
    parser.add_argument("--test-fraction", type=float, default=0.20, help="Holdout test fraction (default: 0.20)")
    parser.add_argument("--val-fraction", type=float, default=0.10, help="Validation fraction of train pool (default: 0.10)")
    parser.add_argument("--rf-estimators", type=int, default=100, help="Random Forest n_estimators")
    parser.add_argument("--rf-depth", type=int, default=None, help="Random Forest max_depth")
    parser.add_argument("--cnn-epochs", type=int, default=10, help="CNN training epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="CNN training batch size")
    parser.add_argument("--output-dir", type=str, default="models/candidates/ton_iot_v2", help="Candidate output directory")
    parser.add_argument("--run-type", choices=["full", "smoke"], default="full", help="Evaluation run type")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    return parser.parse_args()


def run_train_source(args=None):
    if args is None:
        args = parse_args()

    start_time = time.time()
    print("=" * 70)
    print("      SENTRi-X: Source Model Training Pipeline (ToN-IoT)")
    print(f"      Run Type: {args.run_type.upper()} | Seed: {args.seed}")
    print("=" * 70)

    # Step 0: Dependency check
    try:
        import tensorflow as tf
        has_tf = True
        # Set seeds for determinism
        tf.random.set_seed(args.seed)
    except ImportError:
        has_tf = False
        if args.run_type == "full":
            print("\nFATAL ERROR: TensorFlow is required for full model training.", file=sys.stderr)
            print("Cannot substitute a mock CNN for a full training run.", file=sys.stderr)
            print("Please run this command in an environment with TensorFlow installed (e.g. WSL venv).", file=sys.stderr)
            sys.exit(1)
        else:
            print("\nWARNING: TensorFlow not installed. Running in mock smoke mode.")

    np.random.seed(args.seed)

    # 1. Ingestion
    print(f"\n[Step 1] Loading raw ToN-IoT data from {args.data_dir} (sample_n={args.sample_n})...")
    X_encoded, y_binary, info = load_ton_iot(
        args.data_dir,
        max_files=args.max_files,
        sample_n=args.sample_n,
        seed=args.seed,
    )
    print(f"Data ingested: {len(X_encoded)} rows, class counts: {info.get('class_counts')}")

    # 2. Split
    print(f"\n[Step 2] Splitting into disjoint partitions (Test={args.test_fraction*100:.0f}%, Val={args.val_fraction*100:.0f}% of train)...")
    X_train, X_val, X_test, y_train, y_val, y_test, split_manifest = stratified_split(
        X_encoded,
        y_binary,
        test_fraction=args.test_fraction,
        val_fraction=args.val_fraction,
        seed=args.seed,
        domain="ton_iot",
    )
    print(f"Partitions: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    # 3. Preprocessing (Fit on train ONLY)
    print("\n[Step 3] Fitting PreprocessingPipeline strictly on training partition...")
    pipeline = PreprocessingPipeline().fit(X_train)
    X_train_scaled = pipeline.transform(X_train)
    X_val_scaled = pipeline.transform(X_val)
    X_test_scaled = pipeline.transform(X_test)
    print("Transform complete: Train/Val/Test scaled without target leakage.")

    # 4. Train RF
    print(f"\n[Step 4] Training Random Forest (n_estimators={args.rf_estimators})...")
    rf_model = train_rf(
        X_train_scaled,
        y_train,
        n_estimators=args.rf_estimators,
        max_depth=args.rf_depth,
        random_state=args.seed,
    )
    print("Random Forest training complete.")

    # 5. Train CNN
    print(f"\n[Step 5] Training 1D-CNN (epochs={args.cnn_epochs}, batch_size={args.batch_size})...")
    if has_tf:
        cnn_model, history = train_cnn(
            X_train_scaled,
            y_train,
            X_val_scaled,
            y_val,
            epochs=args.cnn_epochs,
            batch_size=args.batch_size,
            verbose=1,
        )
    else:
        class MockCNN:
            def predict(self, X_3d, verbose=0):
                return np.ones((len(X_3d), 1)) * 0.5
        cnn_model = MockCNN()

    # 6. Multi-Mode Independent Holdout Evaluation
    print("\n[Step 6] Evaluating RF, CNN, and Hybrid modes on independent test holdout...")
    p_rf = rf_model.predict_proba(X_test_scaled)[:, 1]
    if has_tf:
        X_test_3d = X_test_scaled.reshape(X_test_scaled.shape[0], NUM_FEATURES, 1)
        p_cnn = cnn_model.predict(X_test_3d, verbose=0).reshape(-1)
    else:
        p_cnn = np.ones(len(X_test_scaled)) * 0.5
    p_hybrid = (p_rf + p_cnn) / 2.0

    y_test_arr = y_test.to_numpy(dtype=int)

    # 7. Package Candidate in Temporary Staging Area
    out_dir = Path(args.output_dir)
    print(f"\n[Step 7] Assembling and hashing model package into: {out_dir}")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        rf_path = tmp_path / "rf_model.joblib"
        cnn_path = tmp_path / "cnn_model.h5"
        pipe_path = tmp_path / "pipeline.joblib"
        split_path = tmp_path / "split_manifest.json"
        evidence_path = tmp_path / "prediction_evidence.csv"
        eval_path = tmp_path / "evaluation_metrics.json"

        joblib.dump(rf_model, rf_path)
        if has_tf:
            cnn_model.save(cnn_path)
        else:
            cnn_path.write_bytes(b"mock_cnn_smoke_placeholder")

        pipeline.save(pipe_path)
        split_manifest.save(split_path)

        rf_hash = file_sha256(rf_path)
        cnn_hash = file_sha256(cnn_path)
        pipe_hash = file_sha256(pipe_path)
        split_hash = file_sha256(split_path)

        # Save prediction-level evidence CSV
        evidence_hash = save_prediction_evidence(
            evidence_path,
            y_true=y_test_arr,
            p_rf=p_rf,
            p_cnn=p_cnn,
            p_hybrid=p_hybrid,
            sample_ids=list(X_test.index),
        )

        # Compute multi-mode metrics with bound artifact hashes
        eval_result = compute_multimode_metrics(
            y_true=y_test_arr,
            p_rf=p_rf,
            p_cnn=p_cnn,
            p_hybrid=p_hybrid,
            domain="ton_iot",
            run_type=args.run_type,
            dataset="ton_iot",
            evaluation_split="independent_test_holdout",
            rf_hash=rf_hash,
            cnn_hash=cnn_hash,
            preprocessor_hash=pipe_hash,
            split_manifest_file="split_manifest.json",
            split_manifest_hash=split_hash,
            evidence_file="prediction_evidence.csv",
            evidence_hash=evidence_hash,
        )
        eval_result.save(eval_path)

        for m_name in ("rf", "cnn", "hybrid"):
            m = eval_result.modes[m_name]
            print(f"  * Mode [{m_name.upper():6s}]: Acc={m['accuracy']:.4f}, Prec={m['precision']:.4f}, Rec={m['recall']:.4f}, F1={m['f1']:.4f}, AUC={m['roc_auc']}")

        manifest = create_package(
            output_dir=out_dir,
            domain="ton_iot",
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            evidence_path=evidence_path,
            training_config=vars(args),
            run_type=args.run_type,
            is_mock=not has_tf,
            notes=f"Source ToN-IoT candidate trained with seed {args.seed}",
        )

    # 8. Validate Package
    print("\n[Step 8] Validating package integrity...")
    validated = validate_package(out_dir, strict_deployable=(args.run_type == "full"))
    print(f"Validation SUCCESS! Package manifest verified in {out_dir}")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"TRAINING COMPLETE in {elapsed:.2f}s | Output: {out_dir}")
    print("=" * 70)
    return validated


if __name__ == "__main__":
    run_train_source()
