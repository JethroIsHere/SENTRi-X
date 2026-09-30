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


def _compute_single_mode_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> dict:
    """Compute binary classification metrics for one mode."""
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    unique_classes = set(np.unique(y_true))
    if unique_classes == {0, 1}:
        try:
            auc = float(roc_auc_score(y_true, y_proba))
        except ValueError:
            auc = None
    else:
        auc = None

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
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

    # Multi-mode metrics: keys 'rf', 'cnn', 'hybrid'
    modes: dict[str, dict] = field(default_factory=dict)

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

    modes = {
        "rf": _compute_single_mode_metrics(y_true, pred_rf, p_rf),
        "cnn": _compute_single_mode_metrics(y_true, pred_cnn, p_cnn),
        "hybrid": _compute_single_mode_metrics(y_true, pred_hybrid, p_hybrid),
    }

    per_domain = {}
    if domain_labels is not None:
        dom_arr = np.asarray(domain_labels)
        for dom in np.unique(dom_arr):
            mask = (dom_arr == dom)
            if np.any(mask):
                y_dom = y_true[mask]
                per_domain[str(dom)] = {
                    "sample_count": int(np.sum(mask)),
                    "rf": _compute_single_mode_metrics(y_dom, pred_rf[mask], p_rf[mask]),
                    "cnn": _compute_single_mode_metrics(y_dom, pred_cnn[mask], p_cnn[mask]),
                    "hybrid": _compute_single_mode_metrics(y_dom, pred_hybrid[mask], p_hybrid[mask]),
                }

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

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        header = [
            "sample_id", "domain", "y_true",
            "p_rf", "p_cnn", "p_hybrid",
            "pred_rf", "pred_cnn", "pred_hybrid",
        ]
        writer.writerow(header)
        for i in range(n):
            row = [
                ids[i], doms[i], y_true[i],
                round(float(p_rf[i]), 6), round(float(p_cnn[i]), 6), round(float(p_hybrid[i]), 6),
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

    # Verify hashes against active manifest if provided
    if active_manifest is not None:
        if result.rf_hash and active_manifest.rf_hash and result.rf_hash != active_manifest.rf_hash:
            return {"available": False, "reason": "RF hash mismatch between model manifest and evaluation evidence."}
        if result.cnn_hash and active_manifest.cnn_hash and result.cnn_hash != active_manifest.cnn_hash:
            return {"available": False, "reason": "CNN hash mismatch between model manifest and evaluation evidence."}
        if result.preprocessor_hash and active_manifest.preprocessor_hash and result.preprocessor_hash != active_manifest.preprocessor_hash:
            return {"available": False, "reason": "Preprocessor hash mismatch between model manifest and evaluation evidence."}

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
