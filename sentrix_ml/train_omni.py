"""Multi-domain Omni Model Training Pipeline.

Pipeline:
1. Validates environment dependencies (TensorFlow required for full run)
2. Ingests bounded samples from ToN-IoT, BoT-IoT, and CIC-IDS2017 with domain tracking
3. Combines them into a canonical multi-domain pool (all 28 features encoded)
4. Stratified disjoint split: 80% train+val, 20% holdout test pool
   - Within train pool: 90% training, 10% validation
5. Fits PreprocessingPipeline strictly on training partition
6. Trains Random Forest on training partition ONLY (no refitting on test data)
7. Trains 1D CNN on training partition with explicit validation data
8. Evaluates RF, CNN, and Hybrid on combined holdout test pool AND per-domain holdouts
9. Exports prediction-level evidence CSV
10. Packages artifacts and validates integrity
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
from sentrix_ml.evaluation import compute_multimode_metrics, save_prediction_evidence
from sentrix_ml.packaging import create_package, validate_package, file_sha256


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

    # Step 0: Dependency check
    try:
        import tensorflow as tf
        has_tf = True
        tf.random.set_seed(args.seed)
    except ImportError:
        has_tf = False
        if args.run_type == "full":
            print("\nFATAL ERROR: TensorFlow is required for full model training.", file=sys.stderr)
            print("Cannot substitute a mock CNN for a full Omni training run.", file=sys.stderr)
            sys.exit(1)
        else:
            print("\nWARNING: TensorFlow not installed. Running in mock smoke mode.")

    np.random.seed(args.seed)

    # 1. Ingest from 3 domains
    print(f"\n[Step 1] Ingesting bounded {args.sample_per_domain} rows from each domain...")
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

    # 6. Evaluation across RF, CNN, and Hybrid (Combined and Per-Domain Holdout)
    print("\n[Step 6] Evaluating RF, CNN, and Hybrid on Combined Holdout Test Set...")
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
    print(f"\n[Step 7] Assembling and hashing Omni candidate package into: {out_dir}")
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
            cnn_path.write_bytes(b"mock_cnn_omni_weights")

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
            domain_labels=list(test_domains),
        )

        # Compute multi-mode metrics including per-domain holdouts
        eval_result = compute_multimode_metrics(
            y_true=y_test_arr,
            p_rf=p_rf,
            p_cnn=p_cnn,
            p_hybrid=p_hybrid,
            domain="omni",
            run_type=args.run_type,
            dataset="omni",
            evaluation_split="omni_combined_test_holdout",
            rf_hash=rf_hash,
            cnn_hash=cnn_hash,
            preprocessor_hash=pipe_hash,
            split_manifest_file="split_manifest.json",
            split_manifest_hash=split_hash,
            evidence_file="prediction_evidence.csv",
            evidence_hash=evidence_hash,
            domain_labels=test_domains.to_numpy(),
        )
        eval_result.save(eval_path)

        for m_name in ("rf", "cnn", "hybrid"):
            m = eval_result.modes[m_name]
            print(f"  * Combined [{m_name.upper():6s}]: Acc={m['accuracy']:.4f}, Prec={m['precision']:.4f}, Rec={m['recall']:.4f}, F1={m['f1']:.4f}, AUC={m['roc_auc']}")

        print("\n--- Per-Domain Holdout Results (Hybrid) ---")
        for dom, dom_res in eval_result.per_domain.items():
            dh = dom_res["hybrid"]
            print(f"  * {dom.upper():12s} ({dom_res['sample_count']:5d} samples): "
                  f"Acc={dh['accuracy']:.4f}, F1={dh['f1']:.4f}, Prec={dh['precision']:.4f}, Rec={dh['recall']:.4f}")

        manifest = create_package(
            output_dir=out_dir,
            domain="omni",
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            evidence_path=evidence_path,
            training_config=vars(args),
            run_type=args.run_type,
            is_mock=not has_tf,
            notes=f"Omni multi-domain candidate trained with seed {args.seed}",
        )

    print("\n[Step 8] Validating package integrity...")
    validated = validate_package(out_dir, strict_deployable=(args.run_type == "full"))
    print(f"Validation SUCCESS! Package manifest verified in {out_dir}")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"OMNI TRAINING COMPLETE in {elapsed:.2f}s | Output: {out_dir}")
    print("=" * 70)
    return validated


if __name__ == "__main__":
    run_train_omni()
