"""Shared inference implementation for all consumers.

This module is the SINGLE implementation of the SENTRi-X hybrid ensemble.
Notebooks, backend ``run_inference``, and evaluation scripts all call
through here.

Key guarantees:
* RF attack probability is ``predict_proba(X)[:, attack_class_index]``.
* CNN probability is ``model.predict(X_3d).reshape(-1)`` (single sigmoid output).
* Hybrid = arithmetic mean of the two attack probabilities.
* Classification boundary: ``p >= 0.5`` → Attack (class 1).
* Probabilities are validated as finite and within [0, 1].
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES, ATTACK_CLASS_INDEX


@dataclass
class InferenceResult:
    """Container for a single-row inference output."""

    prediction: int          # 0 = Benign, 1 = Attack
    confidence: float        # P(predicted class)
    p_rf: Optional[float]    # RF attack probability (None if RF not used)
    p_cnn: Optional[float]   # CNN attack probability (None if CNN not used)
    p_hybrid: float          # Final fused probability used for decision


def _validate_probability(score: float, name: str) -> None:
    if not np.isfinite(score):
        raise RuntimeError(f"{name} returned non-finite probability: {score}")
    if not 0.0 <= score <= 1.0:
        raise RuntimeError(f"{name} probability out of [0,1]: {score}")


def predict_rf(rf_model, X: np.ndarray) -> np.ndarray:
    """Extract RF attack-class probabilities.  Returns shape (n,)."""
    if hasattr(rf_model, "predict_proba"):
        probs = rf_model.predict_proba(X)
        classes = list(getattr(rf_model, "classes_", [0, 1]))
        if ATTACK_CLASS_INDEX not in classes:
            raise RuntimeError(f"RF has no attack class {ATTACK_CLASS_INDEX}.")
        return probs[:, classes.index(ATTACK_CLASS_INDEX)].astype(float)
    # Fallback for models without predict_proba
    return rf_model.predict(X).astype(float)


def predict_cnn(cnn_model, X: np.ndarray) -> np.ndarray:
    """Extract CNN attack probabilities.  Returns shape (n,).

    Handles both single-output sigmoid and two-output softmax architectures.
    """
    X_3d = X.reshape(X.shape[0], X.shape[1], 1)
    raw = np.asarray(cnn_model.predict(X_3d, verbose=0))
    if raw.ndim == 2 and raw.shape[1] > 1:
        return raw[:, ATTACK_CLASS_INDEX].astype(float)
    return raw.reshape(-1).astype(float)


def hybrid_predict(
    X_scaled: np.ndarray,
    *,
    rf_model=None,
    cnn_model=None,
    mode: str = "hybrid",
) -> tuple[np.ndarray, np.ndarray, np.ndarray | None, np.ndarray | None]:
    """Run the hybrid ensemble on scaled features.

    Args:
        X_scaled: (n, 28) scaled feature matrix
        rf_model: fitted sklearn RF (required for rf/hybrid modes)
        cnn_model: fitted Keras CNN (required for cnn/hybrid modes)
        mode: 'hybrid', 'rf', or 'cnn'

    Returns:
        (predictions, probabilities, p_rf_array, p_cnn_array)

    Raises:
        RuntimeError: if a required model is None or returns invalid probs.
    """
    if mode in ("rf", "hybrid") and rf_model is None:
        raise RuntimeError("The selected Random Forest is unavailable.")
    if mode in ("cnn", "hybrid") and cnn_model is None:
        raise RuntimeError("The selected CNN is unavailable.")

    p_rf = p_cnn = None

    if mode in ("rf", "hybrid"):
        p_rf = predict_rf(rf_model, X_scaled)
        for v in p_rf:
            _validate_probability(v, "RF")

    if mode in ("cnn", "hybrid"):
        p_cnn = predict_cnn(cnn_model, X_scaled)
        for v in p_cnn:
            _validate_probability(v, "CNN")

    if mode == "hybrid":
        probability = (p_rf + p_cnn) / 2.0
    elif mode == "rf":
        probability = p_rf
    else:
        probability = p_cnn

    predictions = (probability >= 0.5).astype(int)
    return predictions, probability, p_rf, p_cnn


def run_single_inference(
    X_scaled: np.ndarray,
    *,
    rf_model=None,
    cnn_model=None,
    mode: str = "hybrid",
) -> InferenceResult:
    """Run inference on a single row.  Convenience wrapper around ``hybrid_predict``."""
    if X_scaled.ndim == 1:
        X_scaled = X_scaled.reshape(1, -1)
    assert X_scaled.shape == (1, NUM_FEATURES), (
        f"Expected shape (1, {NUM_FEATURES}), got {X_scaled.shape}"
    )

    preds, probs, p_rf, p_cnn = hybrid_predict(
        X_scaled, rf_model=rf_model, cnn_model=cnn_model, mode=mode,
    )

    prediction = int(preds[0])
    prob = float(probs[0])
    confidence = prob if prediction == 1 else 1.0 - prob

    return InferenceResult(
        prediction=prediction,
        confidence=confidence,
        p_rf=float(p_rf[0]) if p_rf is not None else None,
        p_cnn=float(p_cnn[0]) if p_cnn is not None else None,
        p_hybrid=prob,
    )
