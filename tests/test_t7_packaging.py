"""T7: Artifact Validation and Packaging Tests.

Verifies:
1. Valid package passes validation and returns ModelManifest.
2. Missing or corrupted files (hash mismatch) raise PackageValidationError.
3. Feature ordering mismatch raises PackageValidationError.
4. Incompatible CNN shape raises PackageValidationError.
"""

import tempfile
from pathlib import Path
import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.packaging import (
    ModelManifest,
    validate_package,
    create_package,
    PackageValidationError,
    file_sha256,
)


@pytest.fixture
def dummy_package(tmp_path):
    """Create a temporary valid model package."""
    # 1. Create dummy RF
    rf = RandomForestClassifier(n_estimators=2, random_state=42)
    rf.fit(np.zeros((10, NUM_FEATURES)), [0] * 5 + [1] * 5)
    rf_path = tmp_path / "src_rf.joblib"
    joblib.dump(rf, rf_path)

    # 2. Create dummy CNN file
    cnn_path = tmp_path / "src_cnn.h5"
    cnn_path.write_bytes(b"dummy_cnn_weights_content_12345")

    # 3. Create pipeline
    pipeline = PreprocessingPipeline().fit(np.zeros((10, NUM_FEATURES)))
    pipe_path = tmp_path / "src_pipeline.joblib"
    pipeline.save(pipe_path)

    pkg_dir = tmp_path / "candidate_v1"
    create_package(
        output_dir=pkg_dir,
        domain="omni",
        rf_path=rf_path,
        cnn_path=cnn_path,
        pipeline_path=pipe_path,
        notes="Dummy package for tests",
    )
    return pkg_dir


def test_t7_valid_package_passes(dummy_package):
    """Verify a valid package passes validation."""
    manifest = validate_package(dummy_package)
    assert manifest.domain == "omni"
    assert manifest.ordered_features == EXPECTED_FEATURES
    assert manifest.cnn_input_shape == [NUM_FEATURES, 1]


def test_t7_corrupted_hash_rejected(dummy_package):
    """Verify tampering with a file triggers hash mismatch and PackageValidationError."""
    rf_file = dummy_package / "rf_model.joblib"
    # Tamper with file
    with open(rf_file, "ab") as f:
        f.write(b"tampered_bytes")

    with pytest.raises(PackageValidationError, match="hash mismatch"):
        validate_package(dummy_package)


def test_t7_missing_file_rejected(dummy_package):
    """Verify missing required artifact triggers PackageValidationError."""
    cnn_file = dummy_package / "cnn_model.h5"
    cnn_file.unlink()

    with pytest.raises(PackageValidationError, match="Missing CNN model"):
        validate_package(dummy_package)


def test_t7_feature_schema_mismatch_rejected(dummy_package):
    """Verify package declaring wrong features or ordering is rejected."""
    manifest_path = dummy_package / "manifest.json"
    manifest = ModelManifest.load(manifest_path)
    # Alter features
    manifest.ordered_features = ["duration", "src_bytes"]  # only 2 features!
    manifest.save(manifest_path)

    with pytest.raises(PackageValidationError, match="Feature order mismatch"):
        validate_package(dummy_package)


def test_t7_cnn_shape_mismatch_rejected(dummy_package):
    """Verify incompatible CNN input shape is rejected."""
    manifest_path = dummy_package / "manifest.json"
    manifest = ModelManifest.load(manifest_path)
    manifest.cnn_input_shape = [14, 1]  # 14 instead of 28!
    manifest.save(manifest_path)

    with pytest.raises(PackageValidationError, match="CNN shape mismatch"):
        validate_package(dummy_package)


if __name__ == "__main__":
    import shutil
    tmp = Path(tempfile.mkdtemp())
    try:
        # Run tests directly
        # RF
        rf = RandomForestClassifier(n_estimators=2, random_state=42)
        rf.fit(np.zeros((10, NUM_FEATURES)), [0] * 5 + [1] * 5)
        rf_path = tmp / "src_rf.joblib"
        joblib.dump(rf, rf_path)
        cnn_path = tmp / "src_cnn.h5"
        cnn_path.write_bytes(b"dummy_cnn_weights_content_12345")
        pipeline = PreprocessingPipeline().fit(np.zeros((10, NUM_FEATURES)))
        pipe_path = tmp / "src_pipeline.joblib"
        pipeline.save(pipe_path)
        pkg_dir = tmp / "candidate_v1"
        create_package(
            output_dir=pkg_dir, domain="omni", rf_path=rf_path,
            cnn_path=cnn_path, pipeline_path=pipe_path
        )
        test_t7_valid_package_passes(pkg_dir)
        print("All T7 Packaging tests passed!")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
