"""Evaluation: offline metrics computation with provenance tracking.

Computes classification metrics from predictions across RF, CNN, and Hybrid modes,
exports per-sample prediction evidence, and links results to exact model/preprocessor
hashes and split manifests.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


def _compute_single_mode_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    sample_weight: np.ndarray | None = None,
) -> dict:
    """Compute binary classification metrics for one mode, with optional sample weights."""
    acc = float(accuracy_score(y_true, y_pred, sample_weight=sample_weight))
    prec = float(precision_score(y_true, y_pred, sample_weight=sample_weight, zero_division=0))
    rec = float(recall_score(y_true, y_pred, sample_weight=sample_weight, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, sample_weight=sample_weight, zero_division=0))

    unique_classes = set(np.unique(y_true))
    if unique_classes == {0, 1}:
        try:
            auc = float(roc_auc_score(y_true, y_proba, sample_weight=sample_weight))
        except ValueError:
            auc = None
    else:
        auc = None

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1], sample_weight=sample_weight)
    tn, fp, fn, tp = cm.ravel()

    # Specificity (True Negative Rate) and False Positive Rate
    denom_neg = tn + fp
    specificity = float(tn / denom_neg) if denom_neg > 0 else 0.0
    fpr = float(fp / denom_neg) if denom_neg > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "confusion_matrix": {
            "tn": int(round(tn)) if sample_weight is None else float(round(tn, 2)),
            "fp": int(round(fp)) if sample_weight is None else float(round(fp, 2)),
            "fn": int(round(fn)) if sample_weight is None else float(round(fn, 2)),
            "tp": int(round(tp)) if sample_weight is None else float(round(tp, 2)),
        },
    }


@dataclass
class EvaluationResult:
    """Holds multi-mode computed metrics and complete artifact provenance."""

    model_domain: str = ""
    run_type: str = "smoke"  # "smoke" or "full"
    dataset: str = ""
    evaluation_split: str = "independent_test_holdout"
    sample_count: int = 0
    class_0_count: int = 0
    class_1_count: int = 0

    # Artifact provenance
    rf_hash: Optional[str] = None
    cnn_hash: Optional[str] = None
    preprocessor_hash: Optional[str] = None
    split_manifest_file: Optional[str] = None
    split_manifest_hash: Optional[str] = None
    evidence_file: Optional[str] = None
    evidence_hash: Optional[str] = None

    # Multi-mode metrics: keys 'rf', 'cnn', 'hybrid' (unweighted empirical holdout)
    modes: dict[str, dict] = field(default_factory=dict)

    # Population-weighted metrics: keys 'rf', 'cnn', 'hybrid' (when sampling weights provided)
    weighted_modes: dict[str, dict] = field(default_factory=dict)
    has_sampling_weights: bool = False
    population_weights: dict = field(default_factory=dict)

    # Per-domain breakdown (for Omni)
    per_domain: dict[str, dict] = field(default_factory=dict)

    # Legacy compatibility accessors for top-level hybrid metrics
    @property
    def accuracy(self) -> Optional[float]:
        return self.modes.get("hybrid", {}).get("accuracy")

    @property
    def precision(self) -> Optional[float]:
        return self.modes.get("hybrid", {}).get("precision")

    @property
    def recall(self) -> Optional[float]:
        return self.modes.get("hybrid", {}).get("recall")

    @property
    def f1(self) -> Optional[float]:
        return self.modes.get("hybrid", {}).get("f1")

    @property
    def roc_auc(self) -> Optional[float]:
        return self.modes.get("hybrid", {}).get("roc_auc")

    @property
    def tp(self) -> Optional[int]:
        return self.modes.get("hybrid", {}).get("confusion_matrix", {}).get("tp")

    @property
    def fp(self) -> Optional[int]:
        return self.modes.get("hybrid", {}).get("confusion_matrix", {}).get("fp")

    @property
    def tn(self) -> Optional[int]:
        return self.modes.get("hybrid", {}).get("confusion_matrix", {}).get("tn")

    @property
    def fn(self) -> Optional[int]:
        return self.modes.get("hybrid", {}).get("confusion_matrix", {}).get("fn")

    @property
    def execution_mode(self) -> str:
        return "hybrid"

    def to_dict(self) -> dict:
        d = asdict(self)
        for k, v in d.items():
            if hasattr(v, "item"):
                d[k] = v.item()
            elif isinstance(v, np.integer):
                d[k] = int(v)
            elif isinstance(v, np.floating):
                d[k] = float(v)
        return d

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def load(path: str | Path) -> "EvaluationResult":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return EvaluationResult(**data)


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    *,
    domain: str = "",
    mode: str = "hybrid",
    run_type: str = "smoke",
    dataset: str = "",
) -> EvaluationResult:
    """Compute metrics for a single mode (backward-compatible entry point)."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    y_proba = np.asarray(y_proba, dtype=float)

    mode_metrics = _compute_single_mode_metrics(y_true, y_pred, y_proba)

    result = EvaluationResult(
        model_domain=domain,
        run_type=run_type,
        dataset=dataset or domain,
        sample_count=len(y_true),
        class_0_count=int((y_true == 0).sum()),
        class_1_count=int((y_true == 1).sum()),
        modes={mode: mode_metrics},
    )
    if mode != "hybrid":
        result.modes["hybrid"] = mode_metrics
    return result


def compute_multimode_metrics(
    y_true: np.ndarray,
    *,
    p_rf: np.ndarray,
    p_cnn: np.ndarray,
    p_hybrid: np.ndarray,
    sample_weight: np.ndarray | list | None = None,
    inclusion_probability: np.ndarray | list | None = None,
    population_weights: dict | None = None,
    domain: str = "",
    run_type: str = "smoke",
    dataset: str = "",
    evaluation_split: str = "independent_test_holdout",
    rf_hash: str | None = None,
    cnn_hash: str | None = None,
    preprocessor_hash: str | None = None,
    split_manifest_file: str | None = None,
    split_manifest_hash: str | None = None,
    evidence_file: str | None = None,
    evidence_hash: str | None = None,
    domain_labels: np.ndarray | list | None = None,
) -> EvaluationResult:
    """Compute separate RF, CNN, and Hybrid metrics on the exact same holdout split."""
    y_true = np.asarray(y_true, dtype=int)
    p_rf = np.asarray(p_rf, dtype=float)
    p_cnn = np.asarray(p_cnn, dtype=float)
    p_hybrid = np.asarray(p_hybrid, dtype=float)

    pred_rf = (p_rf >= 0.5).astype(int)
    pred_cnn = (p_cnn >= 0.5).astype(int)
    pred_hybrid = (p_hybrid >= 0.5).astype(int)

    # Unweighted empirical metrics
    modes = {
        "rf": _compute_single_mode_metrics(y_true, pred_rf, p_rf),
        "cnn": _compute_single_mode_metrics(y_true, pred_cnn, p_cnn),
        "hybrid": _compute_single_mode_metrics(y_true, pred_hybrid, p_hybrid),
    }

    # Population-weighted metrics (when weights provided)
    weighted_modes = {}
    has_weights = False
    sw_arr = None
    if sample_weight is not None:
        sw_arr = np.asarray(sample_weight, dtype=float)
        if len(sw_arr) == len(y_true):
            has_weights = bool(np.any(np.abs(sw_arr - 1.0) > 1e-6))
            weighted_modes = {
                "rf": _compute_single_mode_metrics(y_true, pred_rf, p_rf, sample_weight=sw_arr),
                "cnn": _compute_single_mode_metrics(y_true, pred_cnn, p_cnn, sample_weight=sw_arr),
                "hybrid": _compute_single_mode_metrics(y_true, pred_hybrid, p_hybrid, sample_weight=sw_arr),
            }

    per_domain = {}
    if domain_labels is not None:
        dom_arr = np.asarray(domain_labels)
        for dom in np.unique(dom_arr):
            mask = (dom_arr == dom)
            if np.any(mask):
                y_dom = y_true[mask]
                dom_sw = sw_arr[mask] if sw_arr is not None else None
                dom_entry = {
                    "sample_count": int(np.sum(mask)),
                    "rf": _compute_single_mode_metrics(y_dom, pred_rf[mask], p_rf[mask]),
                    "cnn": _compute_single_mode_metrics(y_dom, pred_cnn[mask], p_cnn[mask]),
                    "hybrid": _compute_single_mode_metrics(y_dom, pred_hybrid[mask], p_hybrid[mask]),
                }
                if dom_sw is not None and has_weights:
                    dom_entry["weighted"] = {
                        "rf": _compute_single_mode_metrics(y_dom, pred_rf[mask], p_rf[mask], sample_weight=dom_sw),
                        "cnn": _compute_single_mode_metrics(y_dom, pred_cnn[mask], p_cnn[mask], sample_weight=dom_sw),
                        "hybrid": _compute_single_mode_metrics(y_dom, pred_hybrid[mask], p_hybrid[mask], sample_weight=dom_sw),
                    }
                per_domain[str(dom)] = dom_entry

    return EvaluationResult(
        model_domain=domain,
        run_type=run_type,
        dataset=dataset or domain,
        evaluation_split=evaluation_split,
        sample_count=len(y_true),
        class_0_count=int((y_true == 0).sum()),
        class_1_count=int((y_true == 1).sum()),
        rf_hash=rf_hash,
        cnn_hash=cnn_hash,
        preprocessor_hash=preprocessor_hash,
        split_manifest_file=split_manifest_file,
        split_manifest_hash=split_manifest_hash,
        evidence_file=evidence_file,
        evidence_hash=evidence_hash,
        modes=modes,
        weighted_modes=weighted_modes,
        has_sampling_weights=has_weights,
        population_weights=population_weights or {},
        per_domain=per_domain,
    )


def save_prediction_evidence(
    path: str | Path,
    *,
    y_true: np.ndarray,
    p_rf: np.ndarray,
    p_cnn: np.ndarray,
    p_hybrid: np.ndarray,
    sample_ids: np.ndarray | list | None = None,
    domain_labels: np.ndarray | list | None = None,
    source_files: np.ndarray | list | None = None,
    source_row_indices: np.ndarray | list | None = None,
    group_ids: np.ndarray | list | None = None,
    inclusion_probabilities: np.ndarray | list | None = None,
    sampling_weights: np.ndarray | list | None = None,
) -> str:
    """Save per-sample prediction evidence as a CSV file and return its sha256 hash."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    y_true = np.asarray(y_true, dtype=int)
    p_rf = np.asarray(p_rf, dtype=float)
    p_cnn = np.asarray(p_cnn, dtype=float)
    p_hybrid = np.asarray(p_hybrid, dtype=float)
    pred_rf = (p_rf >= 0.5).astype(int)
    pred_cnn = (p_cnn >= 0.5).astype(int)
    pred_hybrid = (p_hybrid >= 0.5).astype(int)

    n = len(y_true)
    ids = sample_ids if sample_ids is not None else list(range(n))
    doms = domain_labels if domain_labels is not None else [""] * n

    import hashlib
    h = hashlib.sha256()

    has_extras = any(x is not None for x in (source_files, source_row_indices, group_ids,
                                            inclusion_probabilities, sampling_weights))

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if has_extras:
            header = [
                "sample_id", "domain", "source_file", "source_row_index", "group_id",
                "y_true", "inclusion_probability", "sampling_weight",
                "p_rf", "p_cnn", "p_hybrid",
                "pred_rf", "pred_cnn", "pred_hybrid",
            ]
            s_files = source_files if source_files is not None else [""] * n
            s_rows = source_row_indices if source_row_indices is not None else [""] * n
            s_groups = group_ids if group_ids is not None else [""] * n
            s_probs = inclusion_probabilities if inclusion_probabilities is not None else [1.0] * n
            s_weights = sampling_weights if sampling_weights is not None else [1.0] * n
            writer.writerow(header)
            for i in range(n):
                row = [
                    ids[i], doms[i], s_files[i], s_rows[i], s_groups[i],
                    y_true[i], float(s_probs[i]), float(s_weights[i]),
                    float(p_rf[i]), float(p_cnn[i]), float(p_hybrid[i]),
                    pred_rf[i], pred_cnn[i], pred_hybrid[i],
                ]
                writer.writerow(row)
        else:
            header = [
                "sample_id", "domain", "y_true",
                "p_rf", "p_cnn", "p_hybrid",
                "pred_rf", "pred_cnn", "pred_hybrid",
            ]
            writer.writerow(header)
            for i in range(n):
                row = [
                    ids[i], doms[i], y_true[i],
                    float(p_rf[i]), float(p_cnn[i]), float(p_hybrid[i]),
                    pred_rf[i], pred_cnn[i], pred_hybrid[i],
                ]
                writer.writerow(row)

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def format_metrics_for_api(
    result: EvaluationResult,
    mode: str = "hybrid",
    active_manifest: Any = None,
) -> dict:
    """Format evaluation metrics for the /api/model-metrics endpoint.

    Strict provenance requirements:
    1. Returns available: False if run_type != 'full'
    2. Validates artifact hashes match the active manifest
    3. Selects the metrics corresponding to the requested execution mode
    """
    if result.run_type != "full":
        return {
            "available": False,
            "reason": f"Evaluation run_type is '{result.run_type}'. Only 'full' evaluation metrics are published to API.",
            "run_type": result.run_type,
        }

    # Strict provenance verification against active manifest if provided
    if active_manifest is not None:
        if not result.rf_hash or not active_manifest.rf_hash or result.rf_hash != active_manifest.rf_hash:
            return {"available": False, "reason": "RF hash mismatch or missing between model manifest and evaluation evidence."}
        if not result.cnn_hash or not active_manifest.cnn_hash or result.cnn_hash != active_manifest.cnn_hash:
            return {"available": False, "reason": "CNN hash mismatch or missing between model manifest and evaluation evidence."}
        if not result.preprocessor_hash or not active_manifest.preprocessor_hash or result.preprocessor_hash != active_manifest.preprocessor_hash:
            return {"available": False, "reason": "Preprocessor hash mismatch or missing between model manifest and evaluation evidence."}
        if result.model_domain and active_manifest.domain and result.model_domain != active_manifest.domain:
            return {"available": False, "reason": "Domain mismatch between model manifest and evaluation evidence."}
        if active_manifest.split_manifest_hash and result.split_manifest_hash != active_manifest.split_manifest_hash:
            return {"available": False, "reason": "Split manifest hash mismatch between model manifest and evaluation evidence."}
        if active_manifest.evidence_hash and result.evidence_hash != active_manifest.evidence_hash:
            return {"available": False, "reason": "Prediction evidence hash mismatch between model manifest and evaluation evidence."}

    # Select mode-specific metrics
    mode_metrics = result.modes.get(mode)
    if not mode_metrics:
        # Fallback to single mode result if available
        if mode == "hybrid" and result.accuracy is not None:
            mode_metrics = {
                "accuracy": result.accuracy,
                "precision": result.precision,
                "recall": result.recall,
                "f1": result.f1,
                "roc_auc": result.roc_auc,
            }
        else:
            return {"available": False, "reason": f"No evaluation metrics found for execution mode '{mode}'."}

    clean_metrics = {}
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        val = mode_metrics.get(key)
        if val is not None and np.isfinite(val) and 0.0 <= val <= 1.0:
            clean_metrics[key] = float(val)

    if not clean_metrics:
        return {"available": False, "reason": "Evaluation metrics are empty or non-finite."}

    return {
        "available": True,
        "model": result.model_domain,
        "mode": mode,
        "dataset": result.dataset,
        "evaluation_split": result.evaluation_split,
        "source": f"sentrix_ml evaluation ({result.run_type})",
        "metrics": clean_metrics,
        "confusion_matrix": mode_metrics.get("confusion_matrix"),
        "sample_count": result.sample_count,
        "run_type": result.run_type,
    }
