"""T2: Encoding Tests.

Verifies:
1. Equivalent text proto ('tcp') and one-hot ('proto_tcp': 1) yield identical feature rows.
2. Equivalent text conn_state ('SF') and one-hot ('conn_state_SF': 1) yield identical feature rows.
3. Feature ordering strictly adheres to EXPECTED_FEATURES (28 features).
4. Invalid/missing numeric values are safely coerced to 0.0 without crashing.
5. Unknown protocol or connection state sets known one-hot indicators to 0.0.
"""

import numpy as np
import pandas as pd
import pytest

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    NUM_FEATURES,
    NUMERIC_FEATURE_NAMES,
    PROTO_VOCAB,
    CONN_STATE_VOCAB,
)
from sentrix_ml.preprocessing import build_feature_row, encode_dataframe


def test_t2_text_vs_onehot_equivalence():
    """Verify text input yields identical vector to explicit one-hot flags."""
    sample_text = {
        "duration": 1.25,
        "src_bytes": 450,
        "dst_bytes": 1200,
        "src_pkts": 5,
        "dst_pkts": 8,
        "proto": "tcp",
        "conn_state": "SF",
    }
    sample_onehot = {
        "duration": 1.25,
        "src_bytes": 450,
        "dst_bytes": 1200,
        "src_pkts": 5,
        "dst_pkts": 8,
        "proto_tcp": 1,
        "conn_state_SF": 1,
    }

    df_text = build_feature_row(sample_text)
    df_onehot = build_feature_row(sample_onehot)

    assert df_text.shape == (1, NUM_FEATURES)
    assert df_onehot.shape == (1, NUM_FEATURES)
    assert list(df_text.columns) == EXPECTED_FEATURES
    assert list(df_onehot.columns) == EXPECTED_FEATURES

    np.testing.assert_allclose(
        df_text.to_numpy(dtype=float),
        df_onehot.to_numpy(dtype=float),
        err_msg="Text and one-hot representations differ!",
    )


def test_t2_udp_and_state_encoding():
    """Verify UDP and alternative conn_state (e.g. S0) are encoded correctly."""
    sample = {
        "duration": 0.05,
        "src_bytes": 64,
        "dst_bytes": 0,
        "proto": "udp",
        "conn_state": "S0",
    }
    df = build_feature_row(sample)

    assert df.at[0, "proto_udp"] == 1.0
    assert df.at[0, "proto_tcp"] == 0.0
    assert df.at[0, "conn_state_S0"] == 1.0
    assert df.at[0, "conn_state_SF"] == 0.0


def test_t2_unknown_categories():
    """Verify unknown protocol or state does not corrupt known indicators."""
    sample = {
        "proto": "icmp",  # neither tcp nor udp
        "conn_state": "UNKNOWN_STATE",
    }
    df = build_feature_row(sample)

    for p in PROTO_VOCAB:
        assert df.at[0, f"proto_{p}"] == 0.0
    for s in CONN_STATE_VOCAB:
        assert df.at[0, f"conn_state_{s}"] == 0.0


def test_t2_missing_numeric_coercion():
    """Verify '-' or None or NaN in numeric fields coerce cleanly to 0.0."""
    sample = {
        "duration": "-",
        "src_bytes": None,
        "dst_bytes": "invalid_num",
        "missed_bytes": np.nan,
        "proto": "tcp",
    }
    df = build_feature_row(sample)

    assert df.at[0, "duration"] == 0.0
    assert df.at[0, "src_bytes"] == 0.0
    assert df.at[0, "dst_bytes"] == 0.0
    assert df.at[0, "missed_bytes"] == 0.0
    assert df.at[0, "proto_tcp"] == 1.0


def test_t2_dataframe_encoding():
    """Verify encode_dataframe correctly converts a batch DataFrame."""
    raw_df = pd.DataFrame([
        {"duration": 1.0, "proto": "tcp", "conn_state": "SF", "src_bytes": 100},
        {"duration": 2.0, "proto": "udp", "conn_state": "S0", "src_bytes": 200},
    ])
    encoded = encode_dataframe(raw_df)

    assert encoded.shape == (2, NUM_FEATURES)
    assert list(encoded.columns) == EXPECTED_FEATURES
    assert encoded.loc[0, "proto_tcp"] == 1.0
    assert encoded.loc[0, "proto_udp"] == 0.0
    assert encoded.loc[1, "proto_tcp"] == 0.0
    assert encoded.loc[1, "proto_udp"] == 1.0


if __name__ == "__main__":
    test_t2_text_vs_onehot_equivalence()
    test_t2_udp_and_state_encoding()
    test_t2_unknown_categories()
    test_t2_missing_numeric_coercion()
    test_t2_dataframe_encoding()
    print("All T2 Encoding tests passed!")
