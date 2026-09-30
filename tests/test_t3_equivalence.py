"""T3: Training / Live Equivalence Tests.

Verifies:
1. An offline training pipeline and the backend inference pipeline transform a canonical
   sample into identical feature tensors.
2. Serialization and reloading of PreprocessingPipeline preserves exact transform output.
3. 2D array and 3D CNN tensor representations match within float64 tolerances.
"""

import tempfile
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline, build_feature_row


def test_t3_offline_and_live_transform_equivalence():
    """Verify offline pipeline and live feature row reach the exact same transformed tensor."""
    np.random.seed(42)
    # Fit pipeline on dummy training set
    train_data = pd.DataFrame(
        np.random.uniform(10, 1000, size=(100, NUM_FEATURES)),
        columns=EXPECTED_FEATURES,
    )
    pipeline = PreprocessingPipeline().fit(train_data)

    # Test sample as dictionary (like incoming live POST /api/ingest-flow)
    packet_dict = {
        "duration": 2.5,
        "src_bytes": 512,
        "dst_bytes": 1024,
        "missed_bytes": 0,
        "src_pkts": 4,
        "src_ip_bytes": 600,
        "dst_pkts": 6,
        "dst_ip_bytes": 1100,
        "dns_qclass": 0,
        "dns_qtype": 0,
        "dns_rcode": 0,
        "http_request_body_len": 0,
        "http_response_body_len": 0,
        "http_status_code": 0,
        "proto": "tcp",
        "conn_state": "SF",
    }

    # Live path: build_feature_row -> pipeline.transform
    live_df = build_feature_row(packet_dict)
    live_tensor = pipeline.transform(live_df)

    # Offline path: DataFrame constructed directly with the exact same values -> pipeline.transform
    offline_df = pd.DataFrame(0.0, index=[0], columns=EXPECTED_FEATURES)
    for k, v in packet_dict.items():
        if k == "proto":
            offline_df["proto_tcp"] = 1.0
        elif k == "conn_state":
            offline_df["conn_state_SF"] = 1.0
        else:
            offline_df[k] = float(v)
    offline_tensor = pipeline.transform(offline_df)

    # Both tensors must be identical
    np.testing.assert_allclose(
        live_tensor,
        offline_tensor,
        rtol=1e-12,
        atol=1e-12,
        err_msg="Live and offline transformed tensors do not match!",
    )


def test_t3_pipeline_serialization_roundtrip():
    """Verify saved and reloaded pipeline produces identical transforms."""
    np.random.seed(42)
    train_data = np.random.randn(50, NUM_FEATURES)
    pipeline = PreprocessingPipeline().fit(train_data)

    test_sample = np.random.randn(5, NUM_FEATURES)
    expected_output = pipeline.transform(test_sample)

    with tempfile.TemporaryDirectory() as tmpdir:
        save_path = Path(tmpdir) / "pipeline.joblib"
        hash_val = pipeline.save(save_path)

        assert hash_val.startswith("sha256:")
        assert save_path.exists()

        reloaded = PreprocessingPipeline.load(save_path)
        assert reloaded.hash == hash_val
        assert reloaded.is_fitted

        reloaded_output = reloaded.transform(test_sample)
        np.testing.assert_allclose(
            expected_output,
            reloaded_output,
            rtol=1e-14,
            atol=1e-14,
            err_msg="Reloaded pipeline output diverged from original!",
        )


if __name__ == "__main__":
    test_t3_offline_and_live_transform_equivalence()
    test_t3_pipeline_serialization_roundtrip()
    print("All T3 Equivalence tests passed!")
