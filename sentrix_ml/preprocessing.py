"""Preprocessing: encoding, scaling, and feature alignment.

All transformations are applied through a single ``PreprocessingPipeline``
object that can be fitted on training data, serialized, and reloaded for
inference.  The pipeline guarantees:

* Text ``proto`` / ``conn_state`` fields are one-hot encoded consistently.
* Numeric features are coerced, NaN-filled, and optionally scaled.
* Feature order always matches ``EXPECTED_FEATURES``.
* A fitted pipeline records the scaler statistics and can be validated
  against a model manifest hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    NUM_FEATURES,
    NUMERIC_FEATURE_NAMES,
    PROTO_VOCAB,
    CONN_STATE_VOCAB,
)


def _file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


# ── One-hot encoding from text fields ────────────────────────────────

def encode_proto(value: str) -> dict[str, float]:
    """Return one-hot dict for a protocol string."""
    v = str(value).strip().lower()
    return {f"proto_{p}": float(v == p) for p in PROTO_VOCAB}


def encode_conn_state(value: str) -> dict[str, float]:
    """Return one-hot dict for a connection-state string."""
    v = str(value).strip().upper()
    return {f"conn_state_{s}": float(v == s) for s in CONN_STATE_VOCAB}


def build_feature_row(packet: dict | pd.Series) -> pd.DataFrame:
    """Convert a raw packet dict/Series into a single-row DataFrame
    aligned to ``EXPECTED_FEATURES``.

    Handles both:
    - Dictionary payloads with one-hot flags (``proto_tcp=1``)
    - Dictionary/Series with textual ``proto`` / ``conn_state`` fields
    """
    row: dict[str, float] = {f: 0.0 for f in EXPECTED_FEATURES}
    is_dict = isinstance(packet, dict)

    # Numeric features
    for col in NUMERIC_FEATURE_NAMES:
        raw = packet.get(col, 0) if is_dict else (packet[col] if col in packet else 0)
        if raw == "-" or raw is None:
            raw = 0
        coerced = pd.to_numeric(raw, errors="coerce")
        row[col] = float(0.0 if pd.isna(coerced) else coerced)

    # Protocol — accept either one-hot flags or text
    if is_dict:
        has_text_proto = "proto" in packet and not any(
            packet.get(f"proto_{p}") for p in PROTO_VOCAB
        )
        if has_text_proto:
            row.update(encode_proto(packet["proto"]))
        else:
            for p in PROTO_VOCAB:
                key = f"proto_{p}"
                if packet.get(key):
                    row[key] = 1.0
    else:
        if "proto" in packet.index:
            row.update(encode_proto(str(packet["proto"])))

    # Connection state — accept either one-hot flags or text
    if is_dict:
        has_text_cs = "conn_state" in packet and not any(
            packet.get(f"conn_state_{s}") for s in CONN_STATE_VOCAB
        )
        if has_text_cs:
            row.update(encode_conn_state(packet["conn_state"]))
        else:
            for s in CONN_STATE_VOCAB:
                key = f"conn_state_{s}"
                if packet.get(key):
                    row[key] = 1.0
    else:
        if "conn_state" in packet.index:
            row.update(encode_conn_state(str(packet["conn_state"])))

    return pd.DataFrame([row], columns=EXPECTED_FEATURES)


def encode_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Encode a raw DataFrame with ``proto`` and ``conn_state`` text columns
    into aligned numeric features matching ``EXPECTED_FEATURES``.

    Used by dataset adapters and notebooks.
    """
    result = pd.DataFrame(0.0, index=df.index, columns=EXPECTED_FEATURES)

    # Copy numeric features
    for col in NUMERIC_FEATURE_NAMES:
        if col in df.columns:
            result[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    # One-hot encode proto
    if "proto" in df.columns:
        proto_lower = df["proto"].astype(str).str.strip().str.lower()
        for p in PROTO_VOCAB:
            result[f"proto_{p}"] = (proto_lower == p).astype(float)
    else:
        # Check for pre-existing one-hot columns
        for p in PROTO_VOCAB:
            col = f"proto_{p}"
            if col in df.columns:
                result[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    # One-hot encode conn_state
    if "conn_state" in df.columns:
        cs_upper = df["conn_state"].astype(str).str.strip().str.upper()
        for s in CONN_STATE_VOCAB:
            result[f"conn_state_{s}"] = (cs_upper == s).astype(float)
    else:
        for s in CONN_STATE_VOCAB:
            col = f"conn_state_{s}"
            if col in df.columns:
                result[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    return result


# ── Preprocessing Pipeline ───────────────────────────────────────────

@dataclass
class PreprocessingPipeline:
    """Fit-once, apply-everywhere preprocessing.

    The pipeline wraps a ``StandardScaler`` (or None for identity transforms)
    and records its hash for manifest validation.
    """

    scaler: Optional[StandardScaler] = None
    is_fitted: bool = False
    policy: str = "standard_scaler_on_train"
    _hash: Optional[str] = None

    def fit(self, X_train: pd.DataFrame | np.ndarray) -> "PreprocessingPipeline":
        """Fit the scaler on training data only."""
        if isinstance(X_train, pd.DataFrame):
            X_train = X_train.values
        if X_train.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"Expected {NUM_FEATURES} features, got {X_train.shape[1]}"
            )
        self.scaler = StandardScaler()
        self.scaler.fit(X_train)
        self.is_fitted = True
        self._hash = None  # Invalidate cached hash
        return self

    def transform(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Transform features using the fitted scaler."""
        if isinstance(X, pd.DataFrame):
            X = X.values.astype(float)
        if X.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"Expected {NUM_FEATURES} features, got {X.shape[1]}"
            )
        if not self.is_fitted:
            raise RuntimeError("Pipeline has not been fitted. Call .fit() first.")
        if self.scaler is None:
            return X.astype(float)
        return self.scaler.transform(X)

    def fit_transform(self, X_train: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Fit on training data and transform it."""
        self.fit(X_train)
        return self.transform(X_train)

    def save(self, path: str | Path) -> str:
        """Save pipeline to disk, return sha256 hash."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        self._hash = _file_sha256(path)
        return self._hash

    @staticmethod
    def load(path: str | Path) -> "PreprocessingPipeline":
        """Load a saved pipeline from disk."""
        pipeline = joblib.load(path)
        if not isinstance(pipeline, PreprocessingPipeline):
            raise TypeError(f"Expected PreprocessingPipeline, got {type(pipeline)}")
        pipeline._hash = _file_sha256(path)
        return pipeline

    @property
    def hash(self) -> Optional[str]:
        return self._hash

    @staticmethod
    def identity() -> "PreprocessingPipeline":
        """Create a pipeline that performs no scaling (identity transform)."""
        p = PreprocessingPipeline(scaler=None, is_fitted=True, policy="identity")
        return p
