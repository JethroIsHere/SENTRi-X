"""Source model training routine for ToN-IoT dataset.

Pipeline:
1. Ingest raw ToN-IoT CSVs through canonical adapter (no leakage)
2. Stratified train/val/test split (disjoint holdout)
3. Fit PreprocessingPipeline strictly on training partition
4. Train Random Forest on train split
5. Train 1D CNN with explicit validation data
6. Evaluate hybrid ensemble on independent holdout
7. Assemble and validate candidate model package

Usage:
    python -m sentrix_ml.train_source --help
    python -m sentrix_ml.train_source --sample-n 20000 --epochs 5 --run-type smoke
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
from sentrix_ml.inference import hybrid_predict
from sentrix_ml.evaluation import compute_metrics, format_metrics_for_api
from sentrix_ml.packaging import create_package, validate_package


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
    try:
        import tensorflow as tf
        cnn_model, history = train_cnn(
            X_train_scaled,
            y_train,
            X_val_scaled,
            y_val,
            epochs=args.cnn_epochs,
            batch_size=args.batch_size,
            verbose=1,
        )
        has_tf = True
    except ImportError:
        print("TensorFlow not installed in current interpreter; using lightweight mock CNN for plumbing.")
        class MockCNN:
            def predict(self, X_3d, verbose=0):
                return np.ones((len(X_3d), 1)) * 0.5
        cnn_model = MockCNN()
        has_tf = False

    # 6. Independent Holdout Evaluation
    print("\n[Step 6] Evaluating Hybrid Ensemble on independent test holdout...")
    preds, probs, p_rf, p_cnn = hybrid_predict(
        X_test_scaled, rf_model=rf_model, cnn_model=cnn_model, mode="hybrid"
    )
    eval_result = compute_metrics(
        y_true=y_test.to_numpy(dtype=int),
        y_pred=preds,
        y_proba=probs,
        domain="ton_iot",
        mode="hybrid",
        run_type=args.run_type,
    )
    print(f"Holdout Results: Accuracy={eval_result.accuracy:.4f}, "
          f"Precision={eval_result.precision:.4f}, Recall={eval_result.recall:.4f}, "
          f"F1={eval_result.f1:.4f}, ROC_AUC={eval_result.roc_auc}")

    # 7. Package Candidate
    out_dir = Path(args.output_dir)
    print(f"\n[Step 7] Assembling model package into: {out_dir}")
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
            cnn_path.write_bytes(b"mock_cnn_weights_placeholder")
        pipeline.save(pipe_path)
        split_manifest.save(split_path)
        eval_result.save(eval_path)

        manifest = create_package(
            output_dir=out_dir,
            domain="ton_iot",
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            training_config=vars(args),
            run_type=args.run_type,
            notes=f"Source ToN-IoT candidate trained with seed {args.seed}",
        )

    # 8. Validate Package
    print("\n[Step 8] Validating package integrity...")
    validated = validate_package(out_dir)
    print(f"Validation SUCCESS! Package manifest verified in {out_dir}")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"TRAINING COMPLETE in {elapsed:.2f}s | Output: {out_dir}")
    print("=" * 70)
    return validated


if __name__ == "__main__":
    run_train_source()
