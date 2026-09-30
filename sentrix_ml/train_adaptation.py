"""Target domain adaptation pipeline for BoT-IoT and CIC-IDS2017.

Protocol:
1. Load target dataset (raw chunks or mapped CSV fallback) via adapter
2. Adaptation split: 20% study pool (adaptation), 80% exam pool (holdout)
   - Within study pool: 90% adaptation train, 10% validation
3. Fit target PreprocessingPipeline strictly on study train partition
4. Retrain target Random Forest on study train
5. Initialize CNN from source ToN-IoT weights (or build fresh), fine-tune on study train
6. Evaluate on independent 80% exam holdout
7. Package and validate target candidate

Usage:
    python -m sentrix_ml.train_adaptation --domain bot_iot --sample-n 20000 --epochs 5 --run-type smoke
    python -m sentrix_ml.train_adaptation --domain cic_ids2017 --sample-n 20000 --epochs 5 --run-type smoke
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
from sentrix_ml.adapters.bot_iot import load_bot_iot
from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017
from sentrix_ml.splits import adaptation_split
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.training import train_rf, build_cnn_model, train_cnn
from sentrix_ml.inference import hybrid_predict
from sentrix_ml.evaluation import compute_metrics
from sentrix_ml.packaging import create_package, validate_package, ModelManifest


def parse_args():
    parser = argparse.ArgumentParser(description="Target Domain Adaptation for SENTRi-X")
    parser.add_argument("--domain", choices=["bot_iot", "cic_ids2017"], required=True, help="Target domain")
    parser.add_argument("--data-dir", type=str, default=None, help="Path to target data directory")
    parser.add_argument("--source-candidate", type=str, default=None, help="Path to source candidate package for CNN weight transfer")
    parser.add_argument("--sample-n", type=int, default=50000, help="Bounded sample count for memory efficiency")
    parser.add_argument("--study-fraction", type=float, default=0.20, help="Adaptation pool fraction (default: 0.20)")
    parser.add_argument("--val-fraction", type=float, default=0.10, help="Validation fraction of study pool")
    parser.add_argument("--rf-estimators", type=int, default=100, help="Random Forest n_estimators")
    parser.add_argument("--rf-depth", type=int, default=None, help="Random Forest max_depth")
    parser.add_argument("--cnn-epochs", type=int, default=10, help="Fine-tuning epochs")
    parser.add_argument("--batch-size", type=int, default=256, help="Training batch size")
    parser.add_argument("--output-dir", type=str, default=None, help="Output candidate directory")
    parser.add_argument("--run-type", choices=["full", "smoke"], default="full", help="Evaluation run type")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    return parser.parse_args()


def run_train_adaptation(args=None):
    if args is None:
        args = parse_args()

    start_time = time.time()
    domain = args.domain
    default_data_dir = f"data/raw/{domain}"
    data_dir = args.data_dir or default_data_dir
    output_dir = args.output_dir or f"models/candidates/{domain}_v2"

    print("=" * 70)
    print(f"      SENTRi-X: Domain Adaptation Pipeline ({domain.upper()})")
    print(f"      Run Type: {args.run_type.upper()} | Seed: {args.seed}")
    print("=" * 70)

    # 1. Ingestion
    print(f"\n[Step 1] Ingesting {domain} from {data_dir} (sample_n={args.sample_n})...")
    if domain == "bot_iot":
        X_encoded, y_binary, info = load_bot_iot(data_dir, sample_n=args.sample_n, seed=args.seed)
    else:
        X_encoded, y_binary, info = load_cic_ids2017(data_dir, sample_n=args.sample_n, seed=args.seed)
    print(f"Ingested {len(X_encoded)} rows, classes: {info.get('class_counts')}")

    # 2. Split (20% study / 80% exam)
    print(f"\n[Step 2] Executing adaptation split: {args.study_fraction*100:.0f}% Study, {(1-args.study_fraction)*100:.0f}% Exam Holdout...")
    X_s_train, X_s_val, X_exam, y_s_train, y_s_val, y_exam, split_manifest = adaptation_split(
        X_encoded,
        y_binary,
        study_fraction=args.study_fraction,
        val_fraction_of_study=args.val_fraction,
        seed=args.seed,
        domain=domain,
    )
    print(f"Partitions: Study Train={len(X_s_train)}, Study Val={len(X_s_val)}, Exam Holdout={len(X_exam)}")

    # 3. Preprocessing (Fit on Study Train ONLY)
    print("\n[Step 3] Fitting PreprocessingPipeline strictly on Study Train partition...")
    pipeline = PreprocessingPipeline().fit(X_s_train)
    X_train_scaled = pipeline.transform(X_s_train)
    X_val_scaled = pipeline.transform(X_s_val)
    X_exam_scaled = pipeline.transform(X_exam)
    print("Scaling complete: Target study train fitted, exam holdout transformed.")

    # 4. Train Target RF
    print(f"\n[Step 4] Retraining Target Random Forest (n_estimators={args.rf_estimators})...")
    rf_model = train_rf(
        X_train_scaled,
        y_s_train,
        n_estimators=args.rf_estimators,
        max_depth=args.rf_depth,
        random_state=args.seed,
    )
    print("Random Forest target retraining complete.")

    # 5. Initialize & Fine-Tune Target CNN
    print(f"\n[Step 5] Initializing Target CNN (epochs={args.cnn_epochs})...")
    try:
        import tensorflow as tf
        if args.source_candidate:
            source_pkg = Path(args.source_candidate)
            manifest = ModelManifest.load(source_pkg / "manifest.json")
            source_cnn_path = source_pkg / manifest.cnn_file
            print(f"Loading source CNN weights from: {source_cnn_path}")
            cnn_model = tf.keras.models.load_model(source_cnn_path, compile=False)
            cnn_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        else:
            print("No source candidate provided; building canonical architecture...")
            cnn_model = build_cnn_model(input_shape=(NUM_FEATURES, 1))

        X_train_3d = X_train_scaled.reshape(X_train_scaled.shape[0], NUM_FEATURES, 1)
        X_val_3d = X_val_scaled.reshape(X_val_scaled.shape[0], NUM_FEATURES, 1)
        cnn_model.fit(
            X_train_3d,
            y_s_train.to_numpy(dtype=int),
            validation_data=(X_val_3d, y_s_val.to_numpy(dtype=int)),
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

    # 6. Evaluation on 80% Exam Holdout
    print("\n[Step 6] Evaluating on independent 80% Exam Holdout...")
    preds, probs, p_rf, p_cnn = hybrid_predict(
        X_exam_scaled, rf_model=rf_model, cnn_model=cnn_model, mode="hybrid"
    )
    eval_result = compute_metrics(
        y_true=y_exam.to_numpy(dtype=int),
        y_pred=preds,
        y_proba=probs,
        domain=domain,
        mode="hybrid",
        run_type=args.run_type,
    )
    print(f"Exam Holdout ({len(y_exam)} samples): Accuracy={eval_result.accuracy:.4f}, "
          f"Precision={eval_result.precision:.4f}, Recall={eval_result.recall:.4f}, "
          f"F1={eval_result.f1:.4f}, ROC_AUC={eval_result.roc_auc}")

    # 7. Package Candidate
    out_dir = Path(output_dir)
    print(f"\n[Step 7] Packaging adapted model candidate into: {out_dir}")
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
            cnn_path.write_bytes(b"mock_cnn_adapted_weights")
        pipeline.save(pipe_path)
        split_manifest.save(split_path)
        eval_result.save(eval_path)

        manifest = create_package(
            output_dir=out_dir,
            domain=domain,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            training_config=vars(args),
            run_type=args.run_type,
            notes=f"Adapted {domain} candidate trained with seed {args.seed}",
        )

    print("\n[Step 8] Validating package integrity...")
    validated = validate_package(out_dir)
    print(f"Validation SUCCESS! Package manifest verified in {out_dir}")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"ADAPTATION COMPLETE in {elapsed:.2f}s | Output: {out_dir}")
    print("=" * 70)
    return validated


if __name__ == "__main__":
    run_train_adaptation()
