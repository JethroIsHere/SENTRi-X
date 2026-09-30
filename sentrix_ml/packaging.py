"""Model packaging: manifest creation, validation, and activation.

Each candidate model lives in ``models/candidates/<version>/`` with:
* RF weights (.joblib)
* CNN weights (.h5)
* Preprocessing pipeline (.joblib)
* Manifest (manifest.json)
* Optional: evaluation metrics, split manifest, XAI artifacts

The manifest tracks hashes of all artifacts so the backend can validate
integrity before activating a candidate.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np

from sentrix_ml import __version__, SCHEMA_VERSION
from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES


def file_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


@dataclass
class ModelManifest:
    """Describes a complete model package for SENTRi-X."""

    # Identity
    package_version: str = __version__
    schema_version: str = SCHEMA_VERSION
    domain: str = "omni"
    ordered_features: list[str] = field(default_factory=lambda: list(EXPECTED_FEATURES))
    cnn_input_shape: list[int] = field(default_factory=lambda: [NUM_FEATURES, 1])

    # Class mapping
    class_mapping: dict[str, str] = field(
        default_factory=lambda: {"0": "Benign", "1": "Attack"}
    )

    # Preprocessing
    preprocessor_file: str = "pipeline.joblib"
    preprocessor_hash: Optional[str] = None
    preprocessing_policy: str = "standard_scaler_on_train"

    # Model artifacts
    rf_file: str = "rf_model.joblib"
    rf_hash: Optional[str] = None
    cnn_file: str = "cnn_model.h5"
    cnn_hash: Optional[str] = None

    # Training config
    training_config: dict = field(default_factory=dict)

    # Evaluation
    evaluation_run_type: str = "smoke"
    evaluation_file: Optional[str] = None
    evaluation_hash: Optional[str] = None
    split_manifest_file: Optional[str] = None

    # XAI
    xai_background_file: Optional[str] = None
    xai_background_hash: Optional[str] = None

    # Metadata
    created_at: str = ""
    source_revision: str = ""
    notes: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    @staticmethod
    def load(path: str | Path) -> "ModelManifest":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return ModelManifest(**data)


class PackageValidationError(Exception):
    """Raised when a model package fails validation."""
    pass


def validate_package(package_dir: str | Path) -> ModelManifest:
    """Validate all artifacts in a model package directory.

    Checks:
    * manifest.json exists and is parseable
    * All referenced files exist
    * All file hashes match the manifest
    * Feature order matches the current schema
    * CNN input shape is compatible

    Returns the validated manifest.

    Raises:
        PackageValidationError: if any check fails.
    """
    pkg = Path(package_dir)
    manifest_path = pkg / "manifest.json"

    if not manifest_path.exists():
        raise PackageValidationError(f"Missing manifest.json in {pkg}")

    try:
        manifest = ModelManifest.load(manifest_path)
    except (json.JSONDecodeError, TypeError) as e:
        raise PackageValidationError(f"Invalid manifest: {e}") from e

    # Validate feature order
    if manifest.ordered_features != EXPECTED_FEATURES:
        raise PackageValidationError(
            f"Feature order mismatch: manifest has {len(manifest.ordered_features)} "
            f"features, expected {NUM_FEATURES}."
        )

    # Validate CNN input shape
    expected_shape = [NUM_FEATURES, 1]
    if manifest.cnn_input_shape != expected_shape:
        raise PackageValidationError(
            f"CNN shape mismatch: {manifest.cnn_input_shape} vs expected {expected_shape}"
        )

    # Validate file existence and hashes
    checks = [
        (manifest.preprocessor_file, manifest.preprocessor_hash, "preprocessor"),
        (manifest.rf_file, manifest.rf_hash, "RF model"),
        (manifest.cnn_file, manifest.cnn_hash, "CNN model"),
    ]

    for filename, expected_hash, label in checks:
        filepath = pkg / filename
        if not filepath.exists():
            raise PackageValidationError(f"Missing {label}: {filepath}")
        if expected_hash:
            actual_hash = file_sha256(filepath)
            if actual_hash != expected_hash:
                raise PackageValidationError(
                    f"{label} hash mismatch: expected {expected_hash}, "
                    f"got {actual_hash}"
                )

    # Validate evaluation if present
    if manifest.evaluation_file:
        eval_path = pkg / manifest.evaluation_file
        if not eval_path.exists():
            raise PackageValidationError(f"Missing evaluation file: {eval_path}")
        if manifest.evaluation_hash:
            actual = file_sha256(eval_path)
            if actual != manifest.evaluation_hash:
                raise PackageValidationError(
                    f"Evaluation hash mismatch: {manifest.evaluation_hash} vs {actual}"
                )

    return manifest


def create_package(
    output_dir: str | Path,
    *,
    domain: str,
    rf_path: str | Path,
    cnn_path: str | Path,
    pipeline_path: str | Path,
    training_config: dict | None = None,
    evaluation_path: str | Path | None = None,
    split_manifest_path: str | Path | None = None,
    xai_background_path: str | Path | None = None,
    source_revision: str = "",
    run_type: str = "smoke",
    notes: str = "",
) -> ModelManifest:
    """Assemble a model package from individual artifacts.

    Copies all files into ``output_dir`` and creates a validated manifest.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Copy artifacts
    rf_dest = out / "rf_model.joblib"
    cnn_dest = out / "cnn_model.h5"
    pipe_dest = out / "pipeline.joblib"

    shutil.copy2(rf_path, rf_dest)
    shutil.copy2(cnn_path, cnn_dest)
    shutil.copy2(pipeline_path, pipe_dest)

    manifest = ModelManifest(
        domain=domain,
        rf_hash=file_sha256(rf_dest),
        cnn_hash=file_sha256(cnn_dest),
        preprocessor_hash=file_sha256(pipe_dest),
        training_config=training_config or {},
        source_revision=source_revision,
        evaluation_run_type=run_type,
        notes=notes,
    )

    if evaluation_path:
        eval_dest = out / "evaluation_metrics.json"
        shutil.copy2(evaluation_path, eval_dest)
        manifest.evaluation_file = "evaluation_metrics.json"
        manifest.evaluation_hash = file_sha256(eval_dest)

    if split_manifest_path:
        split_dest = out / "split_manifest.json"
        shutil.copy2(split_manifest_path, split_dest)
        manifest.split_manifest_file = "split_manifest.json"

    if xai_background_path:
        bg_dest = out / "xai_background.pkl"
        shutil.copy2(xai_background_path, bg_dest)
        manifest.xai_background_file = "xai_background.pkl"
        manifest.xai_background_hash = file_sha256(bg_dest)

    manifest.save(out / "manifest.json")
    return manifest
