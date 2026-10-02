"""Model packaging: manifest creation, validation, and activation.

Each candidate model lives in ``models/candidates/<version>/`` with:
* RF weights (.joblib)
* CNN weights (.h5)
* Preprocessing pipeline (.joblib)
* Manifest (manifest.json)
* Optional: evaluation metrics, split manifest, prediction evidence, XAI artifacts

The manifest tracks SHA256 hashes of all artifacts.
Validation enforces:
* Exact schema version ('28f-v2')
* Standard class mapping ('0': 'Benign', '1': 'Attack')
* Complete, non-null artifact hashes matching disk contents
* Deep inspection of weights and fitted scalers before activation
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

import numpy as np

from sentrix_ml import __version__, SCHEMA_VERSION
from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES, CLASS_MAPPING


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

    # Identity & Schema contract
    package_version: str = __version__
    schema_version: str = SCHEMA_VERSION
    domain: str = "omni"
    ordered_features: list[str] = field(default_factory=lambda: list(EXPECTED_FEATURES))
    cnn_input_shape: list[int] = field(default_factory=lambda: [NUM_FEATURES, 1])

    # Class mapping (must be 0: Benign, 1: Attack)
    class_mapping: dict[str, str] = field(default_factory=lambda: dict(CLASS_MAPPING))

    # Preprocessing
    preprocessor_file: str = "pipeline.joblib"
    preprocessor_hash: Optional[str] = None
    preprocessing_policy: str = "standard_scaler_on_train"

    # Model artifacts
    rf_file: str = "rf_model.joblib"
    rf_hash: Optional[str] = None
    cnn_file: str = "cnn_model.h5"
    cnn_hash: Optional[str] = None

    # Flags
    is_mock: bool = False

    # Training config
    training_config: dict = field(default_factory=dict)

    # Evaluation & Provenance
    evaluation_run_type: str = "smoke"  # "smoke" or "full"
    evaluation_file: Optional[str] = None
    evaluation_hash: Optional[str] = None
    split_manifest_file: Optional[str] = None
    split_manifest_hash: Optional[str] = None
    evidence_file: Optional[str] = None
    evidence_hash: Optional[str] = None

    # XAI
    xai_background_file: Optional[str] = None
    xai_background_hash: Optional[str] = None

    # Metadata
    created_at: str = ""
    source_revision: str = ""
    source_candidate_manifest_hash: Optional[str] = None
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
        valid_keys = set(ModelManifest.__dataclass_fields__.keys())
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return ModelManifest(**filtered_data)


def get_git_revision() -> str:
    """Retrieve current repository git commit SHA."""
    try:
        import subprocess
        repo_dir = Path(__file__).resolve().parent.parent
        rev = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
            cwd=repo_dir,
        ).strip()
        return rev
    except Exception:
        return ""


class PackageValidationError(Exception):
    """Raised when a model package fails validation."""
    pass


def validate_package(
    package_dir: str | Path,
    *,
    strict_deployable: bool = False,
    target_domain: Optional[str] = None,
) -> ModelManifest:
    """Validate all artifacts in a model package directory.

    Structural inspection checks:
    * manifest.json exists and is parseable
    * Schema version matches SCHEMA_VERSION (28f-v2)
    * Class mapping is strictly {"0": "Benign", "1": "Attack"}
    * Feature order matches EXPECTED_FEATURES
    * All required artifact hashes are non-null and match disk contents

    Strict deployable checks (required before activation):
    * Rejects packages where is_mock is True
    * Rejects packages where evaluation_run_type is 'smoke'
    * Rejects packages where domain does not match target_domain
    * Deep-loads PreprocessingPipeline and verifies it is fitted with 28 features
    * Deep-loads Random Forest and verifies 28 input features and binary classes
    * Deep-loads CNN and verifies input shape (None, 28, 1) and output (None, 1)
    * Tests inference on test vector and verifies finite probability output

    Returns the validated manifest.
    Raises PackageValidationError if any check fails.
    """
    pkg = Path(package_dir)
    manifest_path = pkg / "manifest.json"

    if not manifest_path.exists():
        raise PackageValidationError(f"Missing manifest.json in {pkg}")

    try:
        manifest = ModelManifest.load(manifest_path)
    except Exception as e:
        raise PackageValidationError(f"Invalid manifest: {e}") from e

    # 1. Schema version check
    if manifest.schema_version != SCHEMA_VERSION:
        raise PackageValidationError(
            f"Schema version mismatch: manifest has '{manifest.schema_version}', expected '{SCHEMA_VERSION}'"
        )

    # 2. Class mapping check: must map 0 -> Benign and 1 -> Attack
    cm = {str(k): str(v).lower() for k, v in manifest.class_mapping.items()}
    if cm.get("0") != "benign" or cm.get("1") != "attack":
        raise PackageValidationError(
            f"Invalid class mapping: {manifest.class_mapping}; must map 0 -> Benign and 1 -> Attack"
        )

    # 3. Feature order check
    if manifest.ordered_features != EXPECTED_FEATURES:
        raise PackageValidationError(
            f"Feature order mismatch: manifest has {len(manifest.ordered_features)} features, "
            f"expected {NUM_FEATURES} canonical features in exact order."
        )

    # 4. CNN input shape check
    expected_shape = [NUM_FEATURES, 1]
    if manifest.cnn_input_shape != expected_shape:
        raise PackageValidationError(
            f"CNN shape mismatch: manifest declares {manifest.cnn_input_shape}, expected {expected_shape}"
        )

    # 5. Required hashes must be non-null
    for hash_val, name in [
        (manifest.preprocessor_hash, "preprocessor_hash"),
        (manifest.rf_hash, "rf_hash"),
        (manifest.cnn_hash, "cnn_hash"),
    ]:
        if not hash_val or not hash_val.startswith("sha256:"):
            raise PackageValidationError(f"Manifest missing required non-null hash for: {name}")

    # 6. File existence and hash matching
    checks = [
        (manifest.preprocessor_file, manifest.preprocessor_hash, "preprocessor"),
        (manifest.rf_file, manifest.rf_hash, "RF model"),
        (manifest.cnn_file, manifest.cnn_hash, "CNN model"),
    ]
    if manifest.evaluation_file:
        checks.append((manifest.evaluation_file, manifest.evaluation_hash, "evaluation file"))
    if manifest.split_manifest_file:
        checks.append((manifest.split_manifest_file, manifest.split_manifest_hash, "split manifest"))
    if manifest.evidence_file:
        checks.append((manifest.evidence_file, manifest.evidence_hash, "prediction evidence"))

    for filename, expected_hash, label in checks:
        filepath = pkg / filename
        if not filepath.exists():
            raise PackageValidationError(f"Missing {label} file: {filepath}")
        if expected_hash:
            actual = file_sha256(filepath)
            if actual != expected_hash:
                raise PackageValidationError(
                    f"{label} SHA256 hash mismatch: expected {expected_hash}, got {actual}"
                )

    # 7. Strict deployable validation
    if strict_deployable:
        if manifest.is_mock:
            raise PackageValidationError("Package is marked is_mock=True; cannot activate for production.")
        if manifest.evaluation_run_type == "smoke":
            raise PackageValidationError("Cannot activate a smoke evaluation package for production.")
        if target_domain and manifest.domain != target_domain:
            raise PackageValidationError(
                f"Domain mismatch: candidate domain '{manifest.domain}' does not match target slot '{target_domain}'."
            )

        # Enforce complete evaluation provenance for deployable candidate
        if not manifest.evaluation_file or not manifest.evaluation_hash:
            raise PackageValidationError("Strict deployment requires a non-null evaluation_file and evaluation_hash.")
        if not manifest.split_manifest_file or not manifest.split_manifest_hash:
            raise PackageValidationError("Strict deployment requires a non-null split_manifest_file and split_manifest_hash.")
        if not manifest.evidence_file or not manifest.evidence_hash:
            raise PackageValidationError("Strict deployment requires a non-null evidence_file and evidence_hash.")

        # Deep inspect evaluation metrics linkage
        eval_path = pkg / manifest.evaluation_file
        try:
            from sentrix_ml.evaluation import EvaluationResult
            eval_res = EvaluationResult.load(eval_path)
            if eval_res.rf_hash != manifest.rf_hash:
                raise PackageValidationError(f"Evaluation RF hash {eval_res.rf_hash} does not match manifest RF hash {manifest.rf_hash}")
            if eval_res.cnn_hash != manifest.cnn_hash:
                raise PackageValidationError(f"Evaluation CNN hash {eval_res.cnn_hash} does not match manifest CNN hash {manifest.cnn_hash}")
            if eval_res.preprocessor_hash != manifest.preprocessor_hash:
                raise PackageValidationError(f"Evaluation preprocessor hash {eval_res.preprocessor_hash} does not match manifest preprocessor hash {manifest.preprocessor_hash}")
            if eval_res.model_domain != manifest.domain:
                raise PackageValidationError(f"Evaluation domain {eval_res.model_domain} does not match manifest domain {manifest.domain}")
            if eval_res.split_manifest_hash != manifest.split_manifest_hash:
                raise PackageValidationError(f"Evaluation split manifest hash {eval_res.split_manifest_hash} does not match manifest {manifest.split_manifest_hash}")
            if eval_res.evidence_hash != manifest.evidence_hash:
                raise PackageValidationError(f"Evaluation evidence hash {eval_res.evidence_hash} does not match manifest {manifest.evidence_hash}")
        except PackageValidationError:
            raise
        except Exception as e:
            raise PackageValidationError(f"Evaluation file deep inspection failed: {e}") from e

        # Deep inspect split manifest linkage & lineage
        split_path = pkg / manifest.split_manifest_file
        try:
            from sentrix_ml.splits import SplitManifest
            sm = SplitManifest.load(split_path)
            if not sm.source_file_hashes:
                raise PackageValidationError("Strict deployment requires non-empty source_file_hashes in split manifest.")
            if not sm.train_flow_ids or not sm.val_flow_ids or not sm.test_flow_ids:
                raise PackageValidationError("Strict deployment requires non-empty flow IDs in all split partitions.")
            if sm.duplicate_group_policy != "keep_first_disjoint":
                raise PackageValidationError(f"Invalid duplicate_group_policy in split manifest: '{sm.duplicate_group_policy}'")
            if sm.identity_policy != "raw_record_sha256_v1" or not sm.sampling_metadata:
                raise PackageValidationError("Strict deployment requires raw record identities and the saved sampling audit.")
            seen_ids, seen_groups, seen_duplicates = set(), set(), set()
            for part in ("train", "val", "test"):
                ids = getattr(sm, part + "_flow_ids")
                groups = getattr(sm, part + "_group_ids")
                records = getattr(sm, part + "_records")
                count = getattr(sm, part + "_count")
                counts = getattr(sm, part + "_class_counts")
                if len(ids) != count or len(groups) != count or len(records) != count or len(set(ids)) != count:
                    raise PackageValidationError(f"Inconsistent {part} lineage lengths or repeated source IDs")
                if set(map(str, counts)) != {"0", "1"} or sum(counts.values()) != count or min(counts.values()) < (2 if part == "train" else 1):
                    raise PackageValidationError(f"Insufficient or inconsistent {part} class counts")
                duplicate_ids = {record.get("duplicate_id") for record in records}
                if seen_ids.intersection(ids) or seen_groups.intersection(groups) or seen_duplicates.intersection(duplicate_ids):
                    raise PackageValidationError("Source identities, raw duplicates, or session groups cross partitions")
                for record, flow_id, group_id in zip(records, ids, groups):
                    key = record.get("source_file", "")
                    if manifest.domain == "omni":
                        key = record.get("domain", "") + "/" + key
                    digest = sm.source_file_hashes.get(key)
                    if (not digest or record.get("source_file_hash") != digest or
                        record.get("source_flow_id") != flow_id or record.get("group_id") != group_id or
                        not isinstance(record.get("source_row_index"), int) or record["source_row_index"] < 0):
                        raise PackageValidationError(f"Invalid {part} raw source identity")
                seen_ids.update(ids); seen_groups.update(groups); seen_duplicates.update(duplicate_ids)
        except PackageValidationError:
            raise
        except Exception as e:
            raise PackageValidationError(f"Split manifest deep inspection failed: {e}") from e

        # Lineage check: source_revision
        if not manifest.source_revision or manifest.source_revision.strip() == "":
            raise PackageValidationError("Strict deployment requires a non-empty source_revision (git commit SHA).")

        # Adaptation candidate provenance check
        if manifest.training_config.get("source_candidate") or manifest.source_candidate_manifest_hash:
            if not manifest.source_candidate_manifest_hash or not manifest.source_candidate_manifest_hash.startswith("sha256:"):
                raise PackageValidationError("Adapted package requires a valid non-empty source_candidate_manifest_hash.")

        # Deep inspect preprocessor
        import joblib
        pipe_path = pkg / manifest.preprocessor_file
        try:
            from sentrix_ml.preprocessing import PreprocessingPipeline
            pipeline = joblib.load(pipe_path)
            if not isinstance(pipeline, PreprocessingPipeline):
                raise PackageValidationError(f"Preprocessor is not PreprocessingPipeline (got {type(pipeline)})")
            if not pipeline.is_fitted:
                raise PackageValidationError("Preprocessing pipeline is not fitted.")
            if pipeline.scaler is not None:
                if not hasattr(pipeline.scaler, "mean_") or len(pipeline.scaler.mean_) != NUM_FEATURES:
                    raise PackageValidationError("Scaler mean_ vector missing or feature count != 28.")
        except Exception as e:
            raise PackageValidationError(f"Preprocessor deep inspection failed: {e}") from e

        # Deep inspect RF
        rf_path = pkg / manifest.rf_file
        try:
            rf = joblib.load(rf_path)
            if not hasattr(rf, "predict_proba"):
                raise PackageValidationError("RF model missing predict_proba method.")
            if getattr(rf, "n_features_in_", None) != NUM_FEATURES:
                raise PackageValidationError(f"RF expects {getattr(rf, 'n_features_in_', None)} features, not {NUM_FEATURES}.")
            if list(getattr(rf, "classes_", [])) != [0, 1]:
                raise PackageValidationError(f"RF classes_ must contain 2 classes, got {getattr(rf, 'classes_', None)}.")
        except Exception as e:
            raise PackageValidationError(f"RF model deep inspection failed: {e}") from e

        # Deep inspect CNN
        cnn_path = pkg / manifest.cnn_file
        try:
            import tensorflow as tf
            cnn = tf.keras.models.load_model(cnn_path, compile=False)
            in_shape = cnn.input_shape
            # (None, 28, 1)
            if in_shape[-2:] != (NUM_FEATURES, 1):
                raise PackageValidationError(f"CNN input shape mismatch: {in_shape} does not end with ({NUM_FEATURES}, 1)")
            if cnn.output_shape[-1:] != (1,):
                raise PackageValidationError(f"CNN output shape mismatch: {cnn.output_shape}")
        except ImportError:
            raise PackageValidationError("TensorFlow is required to inspect and validate CNN model for deployment.")
        except Exception as e:
            raise PackageValidationError(f"CNN model deep inspection failed: {e}") from e

        # Inference test
        try:
            from sentrix_ml.inference import run_single_inference
            test_x = np.zeros((1, NUM_FEATURES), dtype=float)
            test_scaled = pipeline.transform(test_x)
            res = run_single_inference(test_scaled, rf_model=rf, cnn_model=cnn, mode="hybrid")
            if not np.isfinite(res.confidence) or not (0.0 <= res.confidence <= 1.0):
                raise PackageValidationError(f"Test inference produced invalid confidence: {res.confidence}")
            if res.prediction not in (0, 1):
                raise PackageValidationError(f"Test inference produced invalid prediction: {res.prediction}")
        except Exception as e:
            raise PackageValidationError(f"Inference smoke test on candidate failed: {e}") from e

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
    evidence_path: str | Path | None = None,
    xai_background_path: str | Path | None = None,
    source_revision: str = "",
    source_candidate_manifest_hash: Optional[str] = None,
    run_type: str = "smoke",
    is_mock: bool = False,
    notes: str = "",
) -> ModelManifest:
    """Assemble a model package from individual artifacts.

    Copies all files into ``output_dir`` and creates a validated manifest with SHA256 hashes.
    """
    out = Path(output_dir)
    if out.exists() and any(out.iterdir()):
        raise PackageValidationError("Candidate directory is not empty; choose a new versioned output path.")
    out.mkdir(parents=True, exist_ok=True)

    rf_dest = out / "rf_model.joblib"
    cnn_dest = out / "cnn_model.h5"
    pipe_dest = out / "pipeline.joblib"

    shutil.copy2(rf_path, rf_dest)
    shutil.copy2(cnn_path, cnn_dest)
    shutil.copy2(pipeline_path, pipe_dest)

    effective_revision = source_revision or get_git_revision()

    manifest = ModelManifest(
        domain=domain,
        rf_hash=file_sha256(rf_dest),
        cnn_hash=file_sha256(cnn_dest),
        preprocessor_hash=file_sha256(pipe_dest),
        is_mock=is_mock,
        training_config=training_config or {},
        source_revision=effective_revision,
        source_candidate_manifest_hash=source_candidate_manifest_hash,
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
        manifest.split_manifest_hash = file_sha256(split_dest)

    if evidence_path:
        ev_dest = out / "prediction_evidence.csv"
        shutil.copy2(evidence_path, ev_dest)
        manifest.evidence_file = "prediction_evidence.csv"
        manifest.evidence_hash = file_sha256(ev_dest)

    if xai_background_path:
        bg_dest = out / "xai_background.pkl"
        shutil.copy2(xai_background_path, bg_dest)
        manifest.xai_background_file = "xai_background.pkl"
        manifest.xai_background_hash = file_sha256(bg_dest)

    manifest.save(out / "manifest.json")
    return manifest
