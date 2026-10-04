"""ToN-IoT baseline helpers shared by the notebook and command-line entry point.

The notebook shows each stage. This module keeps splitting and candidate export
consistent with the CLI; both require a real TensorFlow CNN, even for smoke runs.
Metrics describe the sampled, group-disjoint holdout, not a population estimate.
"""
from __future__ import annotations

import argparse
import platform
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sentrix_ml.provenance import sampling_audit
from sentrix_ml.balancing import balance_training_rows
from sentrix_ml.adapters.ton_iot import load_ton_iot
from sentrix_ml.splits import stratified_split
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.training import train_rf, train_cnn
from sentrix_ml.inference import hybrid_predict
from sentrix_ml.evaluation import compute_multimode_metrics, save_prediction_evidence
from sentrix_ml.packaging import create_package, validate_package, file_sha256

SOURCE_PROTOCOL = "ton_baseline_v1"
SOURCE_EVALUATION_SPLIT = "sampled_group_disjoint_holdout"


def parse_args(args=None):
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
    return parser.parse_args(args)


def split_source_data(X, y, info, *, test_fraction=.20, val_fraction=.10, seed=42):
    """The same declared ToN split for notebook, CLI and source preflight.

    Retain distinct source records and labels, including conflicting labels.
    Duplicate/session groups stay together. Fractions target group counts.
    """
    return stratified_split(
        X, y, metadata=info["metadata"], test_fraction=test_fraction,
        val_fraction=val_fraction, seed=seed, domain="ton_iot",
        duplicate_group_policy="retain_and_group_disjoint",
        conflict_policy="retain_and_group", require_class_support=True,
        source_file_hashes=info["source_file_hashes"],
        exclusion_reasons=info.get("exclusion_reasons"),
        sampling_metadata=sampling_audit(info),
    )


def save_source_candidate(*, args, rf_model, cnn_model, pipeline, split_manifest,
                          X_test, y_test, p_rf, p_cnn, p_hybrid, balancing_audit):
    """Export already-trained models and bind evidence to their exact artifacts.

    This function does not train, select a threshold, resplit, or activate models.
    Ingestion inclusion probabilities are evidence metadata only; group allocation
    does not establish final test-set inclusion probabilities for the population.
    """
    if list(X_test.index) != split_manifest.test_indices or not X_test.index.equals(y_test.index):
        raise ValueError("Holdout rows must match the frozen split manifest in exact order")
    if split_manifest.duplicate_group_policy != "retain_and_group_disjoint":
        raise ValueError("The ToN baseline requires the declared retain-and-group policy")
    y_true = y_test.to_numpy(dtype=int)
    for name, values in (("RF", p_rf), ("CNN", p_cnn), ("Hybrid", p_hybrid)):
        values = np.asarray(values)
        if (values.shape != y_true.shape or not np.isfinite(values).all()
                or ((values < 0) | (values > 1)).any()):
            raise ValueError(f"{name} probabilities must be finite, in [0, 1], and aligned to the holdout")
    if not np.allclose(p_hybrid, (np.asarray(p_rf) + np.asarray(p_cnn)) / 2, rtol=0, atol=1e-12):
        raise ValueError("Hybrid must be the arithmetic mean of RF and CNN probabilities")
    records = pd.DataFrame(split_manifest.test_records)
    if len(records) != len(y_true):
        raise ValueError("Missing holdout source lineage")

    import tensorflow as tf
    import sklearn
    config = dict(vars(args), protocol=SOURCE_PROTOCOL, balancing=balancing_audit,
                  decision_threshold=.5, fusion="arithmetic_mean",
                  evaluation_scope="Empirical metrics on sampled holdout records; no population estimates",
                  weight_scope="CSV inclusion_probability and sampling_weight describe ingestion only; metrics are unweighted",
                  environment={"python": platform.python_version(), "numpy": np.__version__,
                               "pandas": pd.__version__, "scikit-learn": sklearn.__version__,
                               "tensorflow": tf.__version__})
    config = {k: str(v) if isinstance(v, Path) else v for k, v in config.items()}
    with tempfile.TemporaryDirectory(prefix="sentrix-source-export-") as td:
        stage = Path(td)
        rf_path, cnn_path = stage / "rf_model.joblib", stage / "cnn_model.h5"
        pipe_path, split_path = stage / "pipeline.joblib", stage / "split_manifest.json"
        evidence_path, eval_path = stage / "prediction_evidence.csv", stage / "evaluation_metrics.json"
        joblib.dump(rf_model, rf_path)
        cnn_model.save(cnn_path)
        pipeline.save(pipe_path)
        split_manifest.save(split_path)
        evidence_hash = save_prediction_evidence(
            evidence_path, y_true=y_true, p_rf=p_rf, p_cnn=p_cnn, p_hybrid=p_hybrid,
            sample_ids=split_manifest.test_flow_ids,
            domain_labels=["ton_iot"] * len(y_true),
            source_files=records.source_file.tolist(),
            source_row_indices=records.source_row_index.tolist(),
            group_ids=split_manifest.test_group_ids,
            inclusion_probabilities=records.get("inclusion_probability", pd.Series(1., index=records.index)).tolist(),
            sampling_weights=records.get("sampling_weight", pd.Series(1., index=records.index)).tolist(),
        )
        evaluation = compute_multimode_metrics(
            y_true, p_rf=p_rf, p_cnn=p_cnn, p_hybrid=p_hybrid,
            domain="ton_iot", run_type=args.run_type, dataset="ton_iot",
            evaluation_split=SOURCE_EVALUATION_SPLIT,
            rf_hash=file_sha256(rf_path), cnn_hash=file_sha256(cnn_path),
            preprocessor_hash=file_sha256(pipe_path),
            split_manifest_file=split_path.name, split_manifest_hash=file_sha256(split_path),
            evidence_file=evidence_path.name, evidence_hash=evidence_hash,
        )
        evaluation.save(eval_path)
        create_package(
            output_dir=args.output_dir, domain="ton_iot", rf_path=rf_path, cnn_path=cnn_path,
            pipeline_path=pipe_path, split_manifest_path=split_path,
            evaluation_path=eval_path, evidence_path=evidence_path,
            training_config=config, run_type=args.run_type, is_mock=False,
            notes=f"{SOURCE_PROTOCOL}; real RF and CNN; candidate only; {SOURCE_EVALUATION_SPLIT}",
        )
    return validate_package(args.output_dir, strict_deployable=(args.run_type == "full"))


def run_train_source(args=None):
    if args is None or isinstance(args, list):
        args = parse_args(args)
    try:
        import tensorflow as tf
    except ImportError as exc:
        raise RuntimeError("TensorFlow is required for source training, including smoke runs. "
                           "Select the project's TensorFlow environment; no placeholder CNN is used.") from exc
    if Path(args.output_dir).exists() and any(Path(args.output_dir).iterdir()):
        raise ValueError("Candidate output already contains files; choose a new output directory")
    start = time.monotonic()
    tf.keras.backend.clear_session()
    tf.keras.utils.set_random_seed(args.seed)
    print(f"ToN-IoT baseline | {args.run_type} | seed={args.seed}")
    X, y, info = load_ton_iot(args.data_dir, max_files=args.max_files,
                             sample_n=args.sample_n, seed=args.seed)
    X_train, X_val, X_test, y_train, y_val, y_test, manifest = split_source_data(
        X, y, info, test_fraction=args.test_fraction, val_fraction=args.val_fraction, seed=args.seed,
    )
    print(f"Original partitions: train={len(X_train)}, validation={len(X_val)}, test={len(X_test)}")
    pipeline = PreprocessingPipeline().fit(X_train)
    X_train_scaled = pipeline.transform(X_train)
    X_val_scaled = pipeline.transform(X_val)
    X_test_scaled = pipeline.transform(X_test)
    X_fit, y_fit, balancing = balance_training_rows(X_train_scaled, y_train, seed=args.seed)
    rf = train_rf(X_fit, y_fit, n_estimators=args.rf_estimators,
                  max_depth=args.rf_depth, random_state=args.seed)
    cnn, history = train_cnn(X_fit, y_fit, X_val_scaled, y_val,
                             epochs=args.cnn_epochs, batch_size=args.batch_size, verbose=1)
    _, p_hybrid, p_rf, p_cnn = hybrid_predict(X_test_scaled, rf_model=rf, cnn_model=cnn)
    saved = save_source_candidate(
        args=args, rf_model=rf, cnn_model=cnn, pipeline=pipeline, split_manifest=manifest,
        X_test=X_test, y_test=y_test, p_rf=p_rf, p_cnn=p_cnn, p_hybrid=p_hybrid,
        balancing_audit=balancing,
    )
    print(f"Candidate saved in {time.monotonic() - start:.1f}s: {args.output_dir}")
    return saved


if __name__ == "__main__":
    run_train_source()
