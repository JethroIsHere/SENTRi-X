"""XAI wrappers with provenance tracking.

Handles LIME and SHAP reference explanations, ensuring:
* Background data matches the model's representation (raw vs scaled).
* Model provenance is validated before generating explanations.
* Stale artifacts from different domains are flagged as unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

import numpy as np
import pandas as pd

from sentrix_ml.schema import EXPECTED_FEATURES, ATTACK_CLASS_INDEX


@dataclass
class XAIProvenance:
    """Tracks what model/domain an XAI artifact belongs to."""

    model_domain: str = ""
    model_hash: Optional[str] = None  # Hash of the RF model used
    preprocessor_hash: Optional[str] = None
    representation: str = "unknown"  # "raw", "scaled", or "unknown"
    background_file: Optional[str] = None
    background_hash: Optional[str] = None

    def matches(self, *, model_hash: str | None, preprocessor_hash: str | None,
                model_domain: str) -> bool:
        """Check if this provenance matches the active model."""
        if self.model_domain and self.model_domain != model_domain:
            return False
        if self.model_hash and model_hash and self.model_hash != model_hash:
            return False
        if (self.preprocessor_hash and preprocessor_hash
                and self.preprocessor_hash != preprocessor_hash):
            return False
        return True


@dataclass
class ExplanationResult:
    """Container for explanation output."""

    features: list[dict]   # [{"f": "feature_name", "v": 0.1234}, ...]
    method: str            # e.g. "local_rf_lime", "reference_sample_shap", "unavailable"
    target_class: Optional[int] = None
    model: str = ""
    reason: str = ""       # Why unavailable, if applicable


def create_lime_explainer(
    background_data: np.ndarray | pd.DataFrame,
    feature_names: list[str] | None = None,
):
    """Create a LIME TabularExplainer with the given background data.

    The background data MUST be in the same representation as the rows
    that will be explained (both raw, or both scaled).

    Returns the explainer or None if LIME is unavailable.
    """
    try:
        from lime.lime_tabular import LimeTabularExplainer
    except ImportError:
        return None

    if isinstance(background_data, pd.DataFrame):
        if feature_names is None:
            feature_names = list(background_data.columns)
        background_data = background_data.to_numpy(dtype=float)

    if feature_names is None:
        feature_names = list(EXPECTED_FEATURES)

    return LimeTabularExplainer(
        training_data=background_data,
        feature_names=feature_names,
        class_names=["Benign", "Attack"],
        mode="classification",
        discretize_continuous=True,
    )


def explain_with_lime(
    explainer: Any,
    row: np.ndarray,
    predict_fn,
    *,
    num_features: int = 3,
) -> ExplanationResult:
    """Generate a LIME explanation for a single row.

    Args:
        explainer: A LimeTabularExplainer instance
        row: 1D array matching the explainer's feature count
        predict_fn: Function (n_samples, n_features) → (n_samples, 2) probabilities.
                    Must apply the SAME preprocessing the model expects.
        num_features: Number of top features to return.

    Returns:
        ExplanationResult with the top contributing features.
    """
    if explainer is None:
        return ExplanationResult(
            features=[], method="unavailable", reason="LIME not installed"
        )

    try:
        explanation = explainer.explain_instance(
            data_row=row.astype(float),
            predict_fn=predict_fn,
            num_features=num_features,
            top_labels=1,
        )
        labels = explanation.available_labels()
        target = ATTACK_CLASS_INDEX if ATTACK_CLASS_INDEX in labels else labels[0]
        pairs = explanation.as_list(label=target)
        features = [
            {"f": str(expr), "v": round(float(weight), 4)}
            for expr, weight in pairs
        ]
        return ExplanationResult(
            features=features,
            method="local_rf_lime",
            target_class=int(target),
            model="random_forest",
        )
    except Exception as e:
        return ExplanationResult(
            features=[], method="unavailable",
            reason=f"LIME computation failed: {e}",
        )


def reference_shap_explanation(
    inference_row: np.ndarray | pd.DataFrame,
    *,
    X_sample: pd.DataFrame | None,
    shap_values: np.ndarray | None,
    rf_model: Any = None,
    provenance: XAIProvenance | None = None,
    active_domain: str = "",
    active_model_hash: str | None = None,
) -> ExplanationResult:
    """Look up a reference SHAP explanation from stored artifacts.

    Validates provenance: if the stored artifacts don't match the active
    model/domain, returns unavailable instead of stale explanations.
    """
    meta_reason = ""

    # Provenance check
    if provenance and not provenance.matches(
        model_hash=active_model_hash, preprocessor_hash=None,
        model_domain=active_domain,
    ):
        meta_reason = (
            f"Stored SHAP artifacts are from domain '{provenance.model_domain}', "
            f"but active model is '{active_domain}'. Explanation unavailable."
        )
        # Fall through to RF importance as fallback

    if not meta_reason and X_sample is not None and shap_values is not None:
        try:
            if isinstance(inference_row, pd.DataFrame):
                inference_row = inference_row.to_numpy(dtype=float)
            if inference_row.ndim == 2:
                inference_row = inference_row[0]

            common = list(X_sample.columns)
            matrix = X_sample[common].to_numpy(dtype=float)
            target = inference_row[:len(common)]

            idx = int(np.argmin(np.sum((matrix - target) ** 2, axis=1)))
            arr = np.asarray(shap_values)
            n, features = len(X_sample), len(X_sample.columns)
            vector = None

            if arr.ndim == 2 and arr.shape == (n, features):
                vector = arr[idx]
            elif arr.ndim == 3 and arr.shape[0] == 2 and arr.shape[1:] == (n, features):
                vector = arr[1, idx]
            elif arr.ndim == 3 and arr.shape == (n, features, 2):
                vector = arr[idx, :, 1]

            if vector is not None and np.all(np.isfinite(vector)):
                top = np.argsort(np.abs(vector))[-5:][::-1]
                features_list = [
                    {"f": str(X_sample.columns[i]), "v": float(vector[i])}
                    for i in top
                ]
                return ExplanationResult(
                    features=features_list,
                    method="reference_sample_shap",
                    target_class=ATTACK_CLASS_INDEX,
                )
        except Exception as e:
            meta_reason = f"Reference SHAP lookup failed: {e}"

    # Fallback: global RF feature importance
    if rf_model is not None and hasattr(rf_model, "feature_importances_"):
        importances = np.asarray(rf_model.feature_importances_)
        names = getattr(rf_model, "feature_names_in_", EXPECTED_FEATURES)
        if len(importances) == len(names) and np.all(np.isfinite(importances)):
            top = np.argsort(importances)[-5:][::-1]
            features_list = [
                {"f": str(names[i]), "v": float(importances[i])}
                for i in top
            ]
            return ExplanationResult(
                features=features_list,
                method="global_rf_importance",
                model="random_forest",
                reason=meta_reason,
            )

    return ExplanationResult(
        features=[],
        method="unavailable",
        reason=meta_reason or "No SHAP artifacts or RF model available",
    )
