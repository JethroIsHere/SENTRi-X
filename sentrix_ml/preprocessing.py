"""Feature encoding and preprocessing pipeline for SENTRi-X.

Guarantees:
* One canonical encoding and validation path across dict, Series, and DataFrame
* Strict binary flag parsing ('0' is False, not truthy)
* Strict contradiction rejection (e.g. proto='udp' with proto_tcp=1)
* Distinction between required numeric features and optional features
* Scaler fitted strictly on training data; tracks sha256 hash of parameters
* Serialization and reload integrity
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    NUM_FEATURES,
    REQUIRED_NUMERIC_FEATURES,
    OPTIONAL_NUMERIC_FEATURES,
    PROTO_VOCAB,
    CONN_STATE_VOCAB,
)


class EncodingError(ValueError):
    """Raised when feature encoding or contradiction validation fails."""
    pass


def _file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def parse_binary_flag(val: Any, name: str = "flag") -> bool:
    """Parse a binary one-hot flag strictly.

    Returns True for 1, 1.0, True, '1'.
    Returns False for 0, 0.0, False, '0', None, np.nan, ''.
    Raises ValueError for any other value (e.g. '0' is FALSE, never truthy!).
    """
    if val is None or (isinstance(val, (float, np.floating)) and np.isnan(val)) or val == "":
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float, np.integer, np.floating)):
        if val == 1:
            return True
        if val == 0:
            return False
        raise EncodingError(f"Invalid binary flag {name}={val}; must be 0 or 1.")
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("1", "1.0", "true"):
            return True
        if s in ("0", "0.0", "false"):
            return False
        raise EncodingError(f"Invalid binary flag {name}='{val}'; must be '0' or '1'.")
    raise EncodingError(f"Invalid binary flag {name} of type {type(val)}.")


def resolve_protocol(record: dict | pd.Series) -> dict[str, float]:
    """Resolve and validate protocol specification across dict or Series.

    Rejects contradictory protocol representations (e.g. proto='udp' with proto_tcp=1).
    """
    get_fn = (lambda k: record.get(k)) if isinstance(record, dict) else (lambda k: record[k] if k in record else None)

    active_flags = {}
    for p in PROTO_VOCAB:
        key = f"proto_{p}"
        raw = get_fn(key)
        if raw is not None and not (isinstance(raw, float) and np.isnan(raw)) and raw != "":
            active_flags[p] = parse_binary_flag(raw, key)
        else:
            active_flags[p] = False

    true_flags = [p for p, val in active_flags.items() if val]
    if len(true_flags) > 1:
        raise EncodingError(f"Multiple mutually exclusive protocol flags set: {true_flags}")

    text_proto = get_fn("proto")
    if text_proto is not None and not (isinstance(text_proto, float) and np.isnan(text_proto)) and text_proto != "":
        p_text = str(text_proto).strip().lower()
        if true_flags:
            flag_proto = true_flags[0]
            if flag_proto != p_text:
                raise EncodingError(
                    f"Contradiction in protocol: proto='{p_text}' but proto_{flag_proto}=1"
                )
        for p in PROTO_VOCAB:
            raw_flag = get_fn(f"proto_{p}")
            if raw_flag is not None and not (isinstance(raw_flag, float) and np.isnan(raw_flag)) and raw_flag != "":
                flag_val = active_flags[p]
                if p == p_text and not flag_val:
                    raise EncodingError(
                        f"Contradiction in protocol: proto='{p_text}' but proto_{p}=0"
                    )
        return {f"proto_{p}": float(p == p_text) for p in PROTO_VOCAB}
    else:
        return {f"proto_{p}": float(active_flags[p]) for p in PROTO_VOCAB}


def resolve_conn_state(record: dict | pd.Series) -> dict[str, float]:
    """Resolve and validate connection state specification across dict or Series.

    Rejects contradictory connection state representations.
    """
    get_fn = (lambda k: record.get(k)) if isinstance(record, dict) else (lambda k: record[k] if k in record else None)

    active_flags = {}
    for s in CONN_STATE_VOCAB:
        key = f"conn_state_{s}"
        raw = get_fn(key)
        if raw is not None and not (isinstance(raw, float) and np.isnan(raw)) and raw != "":
            active_flags[s] = parse_binary_flag(raw, key)
        else:
            active_flags[s] = False

    true_flags = [s for s, val in active_flags.items() if val]
    if len(true_flags) > 1:
        raise EncodingError(f"Multiple mutually exclusive connection state flags set: {true_flags}")

    text_cs = get_fn("conn_state")
    if text_cs is not None and not (isinstance(text_cs, float) and np.isnan(text_cs)) and text_cs != "":
        cs_text = str(text_cs).strip().upper()
        if true_flags:
            flag_cs = true_flags[0]
            if flag_cs != cs_text:
                raise EncodingError(
                    f"Contradiction in connection state: conn_state='{cs_text}' but conn_state_{flag_cs}=1"
                )
        for s in CONN_STATE_VOCAB:

            raw_flag = get_fn(f"conn_state_{s}")
            if raw_flag is not None and not (isinstance(raw_flag, float) and np.isnan(raw_flag)) and raw_flag != "":
                flag_val = active_flags[s]
                if s == cs_text and not flag_val:
                    raise ValueError(
                        f"Contradictory connection state: conn_state='{cs_text}' but conn_state_{s}=0"
                    )
        return {f"conn_state_{s}": float(s == cs_text) for s in CONN_STATE_VOCAB}
    else:
        return {f"conn_state_{s}": float(active_flags[s]) for s in CONN_STATE_VOCAB}


def resolve_numeric_features(record: dict | pd.Series, strict_required: bool = False) -> dict[str, float]:
    """Extract and validate numeric flow features."""
    get_fn = (lambda k: record.get(k)) if isinstance(record, dict) else (lambda k: record[k] if k in record else None)
    out = {}

    # Optional features (default 0.0)
    for col in OPTIONAL_NUMERIC_FEATURES:
        raw = get_fn(col)
        if raw is None or raw == "" or raw == "-":
            out[col] = 0.0
        else:
            coerced = pd.to_numeric(raw, errors="coerce")
            if pd.isna(coerced):
                out[col] = 0.0
            elif not np.isfinite(coerced):
                raise ValueError(f"Non-finite numeric value in {col}: {raw}")
            else:
                out[col] = float(max(0.0, float(coerced)))

    # Required features
    for col in REQUIRED_NUMERIC_FEATURES:
        raw = get_fn(col)
        if raw is None or raw == "" or raw == "-":
            if strict_required:
                raise ValueError(f"Missing required numeric feature: {col}")
            out[col] = 0.0
        else:
            coerced = pd.to_numeric(raw, errors="coerce")
            if pd.isna(coerced):
                if strict_required:
                    raise ValueError(f"Invalid non-numeric value in required feature {col}: {raw}")
                out[col] = 0.0
            elif not np.isfinite(coerced):
                raise ValueError(f"Non-finite numeric value in {col}: {raw}")
            elif coerced < 0:
                raise ValueError(f"Negative value not permitted in {col}: {coerced}")
            else:
                out[col] = float(coerced)

    return out


def build_feature_row(packet: dict | pd.Series | pd.DataFrame, strict_required: bool = False) -> pd.DataFrame:
    """Convert a single packet dict, Series, or 1-row DataFrame into a DataFrame aligned to EXPECTED_FEATURES.

    Enforces:
    - Identical canonical vector whether input is dict, Series, or one-hot flags
    - Strict binary flag validation ('0' is False, '1' is True)
    - Contradiction detection between text and one-hot flags
    """
    if isinstance(packet, pd.DataFrame):
        if len(packet) == 0:
            raise ValueError("Input DataFrame is empty.")
        packet = packet.iloc[0]

    row: dict[str, float] = {}
    row.update(resolve_numeric_features(packet, strict_required=strict_required))
    row.update(resolve_protocol(packet))
    row.update(resolve_conn_state(packet))

    # Guarantee exact column order
    ordered_values = [row[f] for f in EXPECTED_FEATURES]
    return pd.DataFrame([ordered_values], columns=EXPECTED_FEATURES, dtype=float)



def encode_dataframe(df: pd.DataFrame, strict_required: bool = False) -> pd.DataFrame:
    """Vectorized encoding of a DataFrame with strict consistency checking."""
    result = pd.DataFrame(0.0, index=df.index, columns=EXPECTED_FEATURES)

    # 1. Numerics
    for col in OPTIONAL_NUMERIC_FEATURES:
        if col in df.columns:
            s = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce").fillna(0.0)
            result[col] = s.clip(lower=0.0).astype(float)
        else:
            result[col] = 0.0

    for col in REQUIRED_NUMERIC_FEATURES:
        if col in df.columns:
            s = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce")
            if strict_required and s.isna().any():
                raise ValueError(f"Missing required numeric values in column: {col}")
            result[col] = s.fillna(0.0).astype(float)
        else:
            if strict_required:
                raise ValueError(f"Missing required numeric column: {col}")
            result[col] = 0.0

    # 2. Protocol validation & encoding
    has_text_proto = "proto" in df.columns
    proto_flags_present = [f"proto_{p}" for p in PROTO_VOCAB if f"proto_{p}" in df.columns]

    if has_text_proto and proto_flags_present:
        text_proto = df["proto"].astype(str).str.strip().str.lower()
        for p in PROTO_VOCAB:
            col_name = f"proto_{p}"
            if col_name in df.columns:
                flag_bool = df[col_name].apply(lambda v: parse_binary_flag(v, col_name))
                mismatch = flag_bool & (text_proto != p)
                if mismatch.any():
                    idx = mismatch.idxmax()
                    raise ValueError(
                        f"Contradictory protocol specification at row {idx}: proto='{text_proto.loc[idx]}' but {col_name}=1"
                    )
                neg_mismatch = (~flag_bool) & (text_proto == p)
                if neg_mismatch.any():
                    idx = neg_mismatch.idxmax()
                    raise ValueError(
                        f"Contradictory protocol specification at row {idx}: proto='{text_proto.loc[idx]}' but {col_name}=0"
                    )
        for p in PROTO_VOCAB:
            result[f"proto_{p}"] = (text_proto == p).astype(float)
    elif has_text_proto:
        text_proto = df["proto"].astype(str).str.strip().str.lower()
        for p in PROTO_VOCAB:
            result[f"proto_{p}"] = (text_proto == p).astype(float)
    elif proto_flags_present:
        flag_series_list = []
        for p in PROTO_VOCAB:
            col_name = f"proto_{p}"
            if col_name in df.columns:
                s_bool = df[col_name].apply(lambda v: parse_binary_flag(v, col_name))
                result[col_name] = s_bool.astype(float)
                flag_series_list.append(s_bool)
            else:
                result[col_name] = 0.0
        if len(flag_series_list) > 1:
            multi = sum(flag_series_list) > 1
            if multi.any():
                raise ValueError("Multiple mutually exclusive protocol flags set in DataFrame row.")
    else:
        for p in PROTO_VOCAB:
            result[f"proto_{p}"] = 0.0

    # 3. Connection state validation & encoding
    has_text_cs = "conn_state" in df.columns
    cs_flags_present = [f"conn_state_{s}" for s in CONN_STATE_VOCAB if f"conn_state_{s}" in df.columns]

    if has_text_cs and cs_flags_present:
        text_cs = df["conn_state"].astype(str).str.strip().str.upper()
        for s in CONN_STATE_VOCAB:
            col_name = f"conn_state_{s}"
            if col_name in df.columns:
                flag_bool = df[col_name].apply(lambda v: parse_binary_flag(v, col_name))
                mismatch = flag_bool & (text_cs != s)
                if mismatch.any():
                    idx = mismatch.idxmax()
                    raise ValueError(
                        f"Contradictory connection state at row {idx}: conn_state='{text_cs.loc[idx]}' but {col_name}=1"
                    )
                neg_mismatch = (~flag_bool) & (text_cs == s)
                if neg_mismatch.any():
                    idx = neg_mismatch.idxmax()
                    raise ValueError(
                        f"Contradictory connection state at row {idx}: conn_state='{text_cs.loc[idx]}' but {col_name}=0"
                    )
        for s in CONN_STATE_VOCAB:
            result[f"conn_state_{s}"] = (text_cs == s).astype(float)
    elif has_text_cs:
        text_cs = df["conn_state"].astype(str).str.strip().str.upper()
        for s in CONN_STATE_VOCAB:
            result[f"conn_state_{s}"] = (text_cs == s).astype(float)
    elif cs_flags_present:
        flag_series_list = []
        for s in CONN_STATE_VOCAB:
            col_name = f"conn_state_{s}"
            if col_name in df.columns:
                s_bool = df[col_name].apply(lambda v: parse_binary_flag(v, col_name))
                result[col_name] = s_bool.astype(float)
                flag_series_list.append(s_bool)
            else:
                result[col_name] = 0.0
        if len(flag_series_list) > 1:
            multi = sum(flag_series_list) > 1
            if multi.any():
                raise ValueError("Multiple mutually exclusive connection state flags set in DataFrame row.")
    else:
        for s in CONN_STATE_VOCAB:
            result[f"conn_state_{s}"] = 0.0

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

    def fit(self_or_cls, X_train: pd.DataFrame | np.ndarray = None) -> "PreprocessingPipeline":
        """Fit the scaler on training data only. Can be called on class or instance."""
        if X_train is None:
            inst = PreprocessingPipeline()
            return inst.fit(self_or_cls)
        self = self_or_cls
        if isinstance(X_train, pd.DataFrame):
            X_train = X_train.values
        if X_train.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"Expected {NUM_FEATURES} features, got {X_train.shape[1]}"
            )
        self.scaler = StandardScaler()
        self.scaler.fit(X_train)
        self.is_fitted = True
        self._hash = None
        return self


    def transform(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Transform features using the fitted scaler."""
        if not self.is_fitted:
            raise RuntimeError("Pipeline has not been fitted. Call .fit() first.")
        if isinstance(X, pd.DataFrame):
            X = X.values.astype(float)
        if X.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"Expected {NUM_FEATURES} features, got {X.shape[1]}"
            )
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
