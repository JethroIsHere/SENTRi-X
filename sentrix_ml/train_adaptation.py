"""Target domain adaptation pipeline for BoT-IoT and CIC-IDS2017.

Protocol:
1. Validates environment dependencies (TensorFlow required for full run)
2. Validates source candidate package for CNN weight transfer
3. Ingests target dataset via canonical adapter (no leakage)
4. Adaptation split: 20% study pool (adaptation), 80% exam pool (holdout)
   - Within study pool: 90% adaptation train, 10% validation
5. Fits target PreprocessingPipeline strictly on study train partition
6. Retrains target Random Forest on study train
7. Fine-tunes CNN initialized from verified source candidate weights
8. Evaluates RF, CNN, and Hybrid modes on independent 80% exam holdout
9. Exports prediction-level evidence CSV
10. Packages and validates candidate
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
from sentrix_ml.provenance import sampling_audit
from sentrix_ml.balancing import balance_training_rows
from sentrix_ml.adapters.bot_iot import load_bot_iot
from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017
from sentrix_ml.splits import adaptation_split
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.training import train_rf, build_cnn_model, train_cnn
from sentrix_ml.evaluation import compute_multimode_metrics, save_prediction_evidence
from sentrix_ml.packaging import create_package, validate_package, file_sha256, ModelManifest


def parse_args(args_list: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Target Domain Adaptation for SENTRi-X")
    parser.add_argument("--domain", choices=["bot_iot", "cic_ids2017"], required=True, help="Target domain")
    parser.add_argument("--data-dir", type=str, default=None, help="Path to target data directory")
    parser.add_argument("--source-candidate", type=str, default=None, help="Path to verified source candidate package (required for adaptation)")
    parser.add_argument("--from-scratch-baseline", action="store_true", help="Explicitly train an unadapted baseline from scratch")
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
    return parser.parse_args(args_list)


def run_train_adaptation(args=None):
    if args is None or isinstance(args, list):
        args = parse_args(args)

    start_time = time.time()
    domain = args.domain
    default_data_dir = f"data/raw/{domain}"
    data_dir = args.data_dir or default_data_dir
    output_dir = args.output_dir or f"models/candidates/{domain}_v2"

    print("=" * 70)
    print(f"      SENTRi-X: Domain Adaptation Pipeline ({domain.upper()})")
    print(f"      Run Type: {args.run_type.upper()} | Seed: {args.seed}")
    print("=" * 70)

    # Step 0: Dependency & source candidate checks
    try:
        import tensorflow as tf
        has_tf = True
        tf.random.set_seed(args.seed)
    except ImportError:
        has_tf = False
        if args.run_type == "full":
            print("\nFATAL ERROR: TensorFlow is required for full model training.", file=sys.stderr)
            print("Cannot substitute a mock CNN for a full adaptation run.", file=sys.stderr)
            sys.exit(1)
        else:
            print("\nWARNING: TensorFlow not installed. Running in mock smoke mode.")

    np.random.seed(args.seed)

    if not args.source_candidate and not args.from_scratch_baseline:
        print("\nFATAL ERROR: Target adaptation requires --source-candidate pointing to a validated source package.", file=sys.stderr)
        print("To train an unadapted baseline from scratch, explicitly pass --from-scratch-baseline.", file=sys.stderr)
        sys.exit(1)

    source_cnn_weights_path = None
    source_manifest_hash = None
    if args.source_candidate:
        print(f"\n[Step 0b] Validating source package: {args.source_candidate}...")
        strict_source = (args.run_type == "full")
        source_manifest = validate_package(
            args.source_candidate,
            strict_deployable=strict_source,
            target_domain="ton_iot",
        )
        if source_manifest.domain != "ton_iot":
            raise ValueError(f"Source candidate domain must be 'ton_iot', got '{source_manifest.domain}'")
        if args.run_type == "full":
            if source_manifest.is_mock or source_manifest.evaluation_run_type == "smoke":
                raise ValueError("Target adaptation for full run requires a full non-mock ToN-IoT source candidate.")

        source_manifest_file = Path(args.source_candidate) / "manifest.json"
        source_manifest_hash = file_sha256(source_manifest_file)
        source_cnn_weights_path = Path(args.source_candidate) / source_manifest.cnn_file
        print(f"Source manifest verified (domain={source_manifest.domain}, hash={source_manifest_hash}). Source CNN: {source_cnn_weights_path}")

    # 1. Ingestion
    print(f"\n[Step 1] Ingesting {domain} from {data_dir} (sample_n={args.sample_n})...")
    if domain == "bot_iot":
        X_encoded, y_binary, info = load_bot_iot(data_dir, sample_n=args.sample_n, seed=args.seed)
    else:
        X_encoded, y_binary, info = load_cic_ids2017(data_dir, sample_n=args.sample_n, seed=args.seed)
    print(f"Ingested {len(X_encoded)} rows, classes: {info.get('class_counts')}")

    # 2. Split (20% study / 80% exam)
    X_s_train, X_s_val, X_exam, y_s_train, y_s_val, y_exam, split_manifest = adaptation_split(
        X_encoded,
        y_binary,
        metadata=info.get("metadata"),
        study_fraction=args.study_fraction,
        val_fraction_of_study=args.val_fraction,
        seed=args.seed,
        domain=domain,
        source_file_hashes=info.get("source_file_hashes"),
        exclusion_reasons=info.get("exclusion_reasons"),
        sampling_metadata=sampling_audit(info),
        require_class_support=True,
    )
    print(f"Partitions: Study Train={len(X_s_train)}, Study Val={len(X_s_val)}, Exam Holdout={len(X_exam)}")

    # 3. Preprocessing (Fit on Study Train ONLY)
    print("\n[Step 3] Fitting PreprocessingPipeline strictly on Study Train partition...")
    pipeline = PreprocessingPipeline().fit(X_s_train)
    X_train_scaled = pipeline.transform(X_s_train)
    X_val_scaled = pipeline.transform(X_s_val)
    X_exam_scaled = pipeline.transform(X_exam)
    print("Scaling complete: Target study train fitted, exam holdout transformed.")

    X_fit, y_fit, balancing_audit = balance_training_rows(X_train_scaled, y_s_train, seed=args.seed)

    # 4. Train Target RF
    print(f"\n[Step 4] Retraining Target Random Forest (n_estimators={args.rf_estimators})...")
    rf_model = train_rf(
        X_fit,
        y_fit,
        n_estimators=args.rf_estimators,
        max_depth=args.rf_depth,
        random_state=args.seed,
    )
    print("Random Forest target retraining complete.")

    # 5. Initialize & Fine-Tune Target CNN
    print(f"\n[Step 5] Initializing Target CNN (epochs={args.cnn_epochs})...")
    if has_tf:
        if source_cnn_weights_path and source_cnn_weights_path.exists():
            print(f"Loading source CNN weights from: {source_cnn_weights_path}")
            cnn_model = tf.keras.models.load_model(source_cnn_weights_path, compile=False)
            cnn_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        else:
            print("Building fresh CNN architecture (from-scratch baseline)...")
            cnn_model = build_cnn_model(input_shape=(NUM_FEATURES, 1))

        X_train_3d = X_fit.reshape(X_fit.shape[0], NUM_FEATURES, 1)
        X_val_3d = X_val_scaled.reshape(X_val_scaled.shape[0], NUM_FEATURES, 1)
        cnn_model.fit(
            X_train_3d,
            y_fit,
            validation_data=(X_val_3d, y_s_val.to_numpy(dtype=int)),
            epochs=args.cnn_epochs,
            batch_size=args.batch_size,
            verbose=1,
        )
    else:
        class MockCNN:
            def predict(self, X_3d, verbose=0):
                return np.ones((len(X_3d), 1)) * 0.5
        cnn_model = MockCNN()

    # 6. Evaluation on 80% Exam Holdout across RF, CNN, and Hybrid
    print("\n[Step 6] Evaluating RF, CNN, and Hybrid on independent 80% Exam Holdout...")
    p_rf = rf_model.predict_proba(X_exam_scaled)[:, 1]
    if has_tf:
        X_exam_3d = X_exam_scaled.reshape(X_exam_scaled.shape[0], NUM_FEATURES, 1)
        p_cnn = cnn_model.predict(X_exam_3d, verbose=0).reshape(-1)
    else:
        p_cnn = np.ones(len(X_exam_scaled)) * 0.5
    p_hybrid = (p_rf + p_cnn) / 2.0

    y_exam_arr = y_exam.to_numpy(dtype=int)

    # 7. Package Candidate in Temporary Staging Area
    out_dir = Path(output_dir)
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
            cnn_path.write_bytes(b"mock_cnn_adapted_weights")

        pipeline.save(pipe_path)
        split_manifest.save(split_path)

        rf_hash = file_sha256(rf_path)
        cnn_hash = file_sha256(cnn_path)
        pipe_hash = file_sha256(pipe_path)
        split_hash = file_sha256(split_path)

        # Save prediction-level evidence CSV
        evidence_hash = save_prediction_evidence(
            evidence_path,
            y_true=y_exam_arr,
            p_rf=p_rf,
            p_cnn=p_cnn,
            p_hybrid=p_hybrid,
            sample_ids=list(X_exam.index),
        )

        # Compute multi-mode metrics
        eval_result = compute_multimode_metrics(
            y_true=y_exam_arr,
            p_rf=p_rf,
            p_cnn=p_cnn,
            p_hybrid=p_hybrid,
            domain=domain,
            run_type=args.run_type,
            dataset=domain,
            evaluation_split="adaptation_exam_holdout",
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

        training_cfg = dict(vars(args), balancing=balancing_audit)
        if source_manifest_hash:
            training_cfg["source_candidate_manifest_hash"] = source_manifest_hash

        manifest = create_package(
            output_dir=out_dir,
            domain=domain,
            rf_path=rf_path,
            cnn_path=cnn_path,
            pipeline_path=pipe_path,
            split_manifest_path=split_path,
            evaluation_path=eval_path,
            evidence_path=evidence_path,
            training_config=training_cfg,
            source_candidate_manifest_hash=source_manifest_hash,
            run_type=args.run_type,
            is_mock=not has_tf,
            notes=f"Adapted {domain} candidate trained with seed {args.seed}",
        )

    print("\n[Step 8] Validating package integrity...")
    validated = validate_package(out_dir, strict_deployable=(args.run_type == "full"))
    print(f"Validation SUCCESS! Package manifest verified in {out_dir}")

    elapsed = time.time() - start_time
    print("=" * 70)
    print(f"ADAPTATION COMPLETE in {elapsed:.2f}s | Output: {out_dir}")
    print("=" * 70)
    return validated


if __name__ == "__main__":
    run_train_adaptation()
