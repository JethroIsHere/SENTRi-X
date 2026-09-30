"""Multi-domain Omni Model Training Pipeline.

Pipeline:
1. Ingests samples from ToN-IoT, BoT-IoT, and CIC-IDS2017 with domain tracking
2. Combines them into a canonical multi-domain pool (all 28 features encoded)
3. Stratified disjoint split: 80% train+val, 20% holdout test pool
   - Within train pool: 90% training, 10% validation
4. Fits PreprocessingPipeline strictly on training partition
5. Trains Random Forest on training partition ONLY (no refitting on test data)
6. Trains 1D CNN on training partition with explicit validation data
7. Evaluates on combined holdout test pool AND per-domain holdout slices
8. Packages artifacts and validates integrity

Usage:
    python -m sentrix_ml.train_omni --sample-per-domain 10000 --epochs 5 --run-type smoke
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
from sentrix_ml.adapters.bot_iot import load_bot_iot
from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017
from sentrix_ml.splits import stratified_split
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.training import train_rf, build_cnn_model, train_cnn
from sentrix_ml.inference import hybrid_predict
from sentrix_ml.evaluation import compute_metrics
from sentrix_ml.packaging import create_package, validate_package


def parse_args():
    parser = argparse.ArgumentParser(description="Multi-Domain Omni Model Training for SENTRi-X")
    parser.add_argument("--sample-per-domain", type=int, default=30000, help="Bounded rows per domain for 16GB RAM limit")
    parser.add_argument("--test-fraction", type=float, default=0.20, help="Holdout test fraction")
    parser.add_argument("--val-fraction", type=float, default=0.10, help="Validation fraction of train pool")
    parser.add_argument("--rf-estimators", type=int, default=100, help="Random Forest n_estimators")
    parser.add_argument("--rf-depth", type=int, default=None, help="Random Forest max_depth")
    parser.add_argument("--cnn-epochs", type=int, default=10, help="CNN training epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="CNN training batch size")
    parser.add_argument("--output-dir", type=str, default="models/candidates/omni_v2", help="Candidate output directory")
    parser.add_argument("--run-type", choices=["full", "smoke"], default="full", help="Evaluation run type")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    return parser.parse_args()


def run_train_omni(args=None):
    if args is None:
        args = parse_args()

    start_time = time.time()
    print("=" * 70)
    print("      SENTRi-X: Multi-Domain Omni Model Training Pipeline")
    print(f"      Run Type: {args.run_type.upper()} | Seed: {args.seed}")
    print("=" * 70)

    # 1. Ingest from 3 domains
    print(f"\n[Step 1] Ingesting {args.sample_per_domain} rows from each domain...")
    project_root = Path(__file__).resolve().parent.parent
    
    # Domain 1: ToN-IoT
    print("  * Ingesting ToN-IoT...")
    X_ton, y_ton, _ = load_ton_iot(project_root / "data" / "raw" / "ton_iot", sample_n=args.sample_per_domain, seed=args.seed)
    domain_ton = pd.Series(["ton_iot"] * len(X_ton), index=X_ton.index)

    # Domain 2: BoT-IoT
    print("  * Ingesting BoT-IoT...")
    X_bot, y_bot, _ = load_bot_iot(project_root / "data" / "raw" / "bot_iot", sample_n=args.sample_per_domain, seed=args.seed)
    domain_bot = pd.Series(["bot_iot"] * len(X_bot), index=X_bot.index)

    # Domain 3: CIC-IDS2017
    print("  * Ingesting CIC-IDS2017...")
    X_cic, y_cic, _ = load_cic_ids2017(project_root / "data" / "raw" / "cic_ids2017", sample_n=args.sample_per_domain, seed=args.seed)
    domain_cic = pd.Series(["cic_ids2017"] * len(X_cic), index=X_cic.index)

    # Combine
    X_omni = pd.concat([X_ton, X_bot, X_cic], ignore_index=True)
    y_omni = pd.concat([y_ton, y_bot, y_cic], ignore_index=True)
    domains = pd.concat([domain_ton, domain_bot, domain_cic], ignore_index=True)

    print(f"Total Combined Omni Dataset: {len(X_omni)} rows, Class Counts: {dict(y_omni.value_counts())}")

    # 2. Split
    print(f"\n[Step 2] Executing stratified split: {args.test_fraction*100:.0f}% Test Holdout, {args.val_fraction*100:.0f}% Val...")
    X_train, X_val, X_test, y_train, y_val, y_test, split_manifest = stratified_split(
        X_omni,
        y_omni,
        test_fraction=args.test_fraction,
        val_fraction=args.val_fraction,
        seed=args.seed,
        domain="omni",
    )
    test_domains = domains.loc[X_test.index]
    print(f"Partitions: Train={len(X_train)}, Val={len(X_val)}, Test Holdout={len(X_test)}")

    # 3. Fit Preprocessing strictly on train
    print("\n[Step 3] Fitting PreprocessingPipeline strictly on Omni Train partition...")
    pipeline = PreprocessingPipeline().fit(X_train)
    X_train_scaled = pipeline.transform(X_train)
    X_val_scaled = pipeline.transform(X_val)
    X_test_scaled = pipeline.transform(X_test)
    print("Scaling complete: Disjoint train/val/test transformed without test leakage.")

    # 4. Train Deployment RF (on Train ONLY)
    print(f"\n[Step 4] Training Omni Deployment Random Forest (n_estimators={args.rf_estimators})...")
    rf_model = train_rf(
        X_train_scaled,
        y_train,
        n_estimators=args.rf_estimators,
        max_depth=args.rf_depth,
        random_state=args.seed,
    )
    print("Omni Random Forest trained (strictly on train partition, zero test rows seen).")

    # 5. Train Deployment CNN
    print(f"\n[Step 5] Training Omni 1D-CNN (epochs={args.cnn_epochs})...")
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
        print("TensorFlow not installed in current interpreter; using mock CNN for plumbing.")
        class MockCNN:
            def predict(self, X_3d, verbose=0):
                return np.ones((len(X_3d), 1)) * 0.5
        cnn_model = MockCNN()
        has_tf = False

    # 6. Evaluation (Combined and Per-Domain Holdout)
    print("\n[Step 6] Evaluating on Combined Holdout Test Set...")
    preds, probs, p_rf, p_cnn = hybrid_predict(
        X_test_scaled, rf_model=rf_model, cnn_model=cnn_model, mode="hybrid"
    )
    eval_result = compute_metrics(
        y_true=y_test.to_numpy(dtype=int),
        y_pred=preds,
        y_proba=probs,
        domain="omni",
        mode="hybrid",
        run_type=args.run_type,
    )
    print(f"Combined Omni Holdout ({len(y_test)} samples): "
          f"Accuracy={eval_result.accuracy:.4f}, Precision={eval_result.precision:.4f}, "
          f"Recall={eval_result.recall:.4f}, F1={eval_result.f1:.4f}, ROC_AUC={eval_result.roc_auc}")

    print("\n--- Per-Domain Holdout Slices ---")
    for dom in ["ton_iot", "bot_iot", "cic_ids2017"]:
        mask = (test_domains == dom).to_numpy()
        if np.any(mask):
            dom_y_true = y_test.to_numpy(dtype=int)[mask]
            dom_preds = preds[mask]
            dom_probs = probs[mask]
            dom_eval = compute_metrics(
                y_true=dom_y_true,
                y_pred=dom_preds,
                y_proba=dom_probs,
                domain=f"omni_slice_{dom}",
                mode="hybrid",
                run_type=args.run_type,
            )
            print(f"  * {dom.upper():12s} ({np.sum(mask):5d} samples): "
                  f"Acc={dom_eval.accuracy:.4f}, F1={dom_eval.f1:.4f}, Prec={dom_eval.precision:.4f}, Rec={dom_eval.recall:.4f}")

    # 7. Package Candidate
    out_dir = Path(args.output_dir)
    print(f"\n[Step 7] Packaging Omni candidate into: {out_dir}")
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
            cnn_path.write_bytes(b"mock_cnn_omni_weights")
        pipeline.save(pipe_path)
        split_manifest.save(split_path)
        eval_result.save(eval_path)

        manifest = create_package(
            output_dir=out_dir,
            domain="omni",
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            training_config=vars(args),
            run_type=args.run_type,
            notes=f"Omni multi-domain candidate trained with seed {args.seed}",
        )

    print("\n[Step 8] Validating package integrity...")
    validated = validate_package(out_dir)
    print(f"Validation SUCCESS! Package manifest verified in {out_dir}")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"OMNI TRAINING COMPLETE in {elapsed:.2f}s | Output: {out_dir}")
    print("=" * 70)
    return validated


if __name__ == "__main__":
    run_train_omni()
