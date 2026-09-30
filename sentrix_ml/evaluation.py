"""Evaluation: offline metrics computation with provenance tracking.

Computes classification metrics from predictions, exports per-sample
evidence, and links results to the model/preprocessor that produced them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


@dataclass
class EvaluationResult:
    """Holds computed metrics and their provenance."""

    # Provenance
    model_domain: str = ""
    execution_mode: str = "hybrid"
    run_type: str = "smoke"  # "smoke" or "full"
    manifest_hash: Optional[str] = None
    rf_hash: Optional[str] = None
    cnn_hash: Optional[str] = None
    preprocessor_hash: Optional[str] = None

    # Dataset info
    dataset: str = ""
    evaluation_split: str = ""
    sample_count: int = 0
    class_0_count: int = 0
    class_1_count: int = 0

    # Metrics
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    roc_auc: Optional[float] = None

    # Confusion matrix
    tn: int = 0
    fp: int = 0
    fn: int = 0
    tp: int = 0

    # Per-domain breakdown (for Omni)
    per_domain: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        for k, v in d.items():
            if hasattr(v, "item"):
                d[k] = v.item()
            elif isinstance(v, (np.integer,)):
                d[k] = int(v)
            elif isinstance(v, (np.floating,)):
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
            return EvaluationResult(**json.load(f))


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    *,
    domain: str = "",
    mode: str = "hybrid",
    run_type: str = "smoke",
) -> EvaluationResult:
    """Compute binary classification metrics.

    Args:
        y_true: Ground truth binary labels (0/1)
        y_pred: Predicted binary labels (0/1)
        y_proba: Predicted attack probabilities (continuous)
        domain: Model domain identifier
        mode: Execution mode ('hybrid', 'rf', 'cnn')
        run_type: 'smoke' or 'full'

    Returns:
        EvaluationResult with computed metrics.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    y_proba = np.asarray(y_proba, dtype=float)

    result = EvaluationResult(
        model_domain=domain,
        execution_mode=mode,
        run_type=run_type,
        sample_count=len(y_true),
        class_0_count=int((y_true == 0).sum()),
        class_1_count=int((y_true == 1).sum()),
    )

    result.accuracy = float(accuracy_score(y_true, y_pred))

    # Precision/recall/F1 for attack class
    result.precision = float(precision_score(y_true, y_pred, zero_division=0))
    result.recall = float(recall_score(y_true, y_pred, zero_division=0))
    result.f1 = float(f1_score(y_true, y_pred, zero_division=0))

    # ROC-AUC: only valid when both classes are represented
    unique_classes = set(np.unique(y_true))
    if unique_classes == {0, 1}:
        result.roc_auc = float(roc_auc_score(y_true, y_proba))
    else:
        result.roc_auc = None  # Explicitly undefined

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    result.tn = int(tn)
    result.fp = int(fp)
    result.fn = int(fn)
    result.tp = int(tp)

    return result


def save_prediction_evidence(
    path: str | Path,
    *,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    p_rf: np.ndarray | None = None,
    p_cnn: np.ndarray | None = None,
    p_hybrid: np.ndarray | None = None,
    sample_ids: np.ndarray | list | None = None,
    domain_labels: np.ndarray | list | None = None,
) -> None:
    """Save per-sample prediction evidence as a compressed .npz file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    arrays = {
        "y_true": np.asarray(y_true),
        "y_pred": np.asarray(y_pred),
    }
    if p_rf is not None:
        arrays["p_rf"] = np.asarray(p_rf)
    if p_cnn is not None:
        arrays["p_cnn"] = np.asarray(p_cnn)
    if p_hybrid is not None:
        arrays["p_hybrid"] = np.asarray(p_hybrid)
    if sample_ids is not None:
        arrays["sample_ids"] = np.asarray(sample_ids)
    if domain_labels is not None:
        arrays["domain_labels"] = np.asarray(domain_labels)

    np.savez_compressed(path, **arrays)


def format_metrics_for_api(result: EvaluationResult) -> dict:
    """Format an evaluation result for the ``/api/model-metrics`` endpoint.

    Returns a dict matching the existing API contract.
    """
    metrics = {}
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        value = getattr(result, key)
        if value is not None and np.isfinite(value) and 0.0 <= value <= 1.0:
            metrics[key] = value

    return {
        "available": bool(metrics) and result.run_type == "full",
        "model": result.model_domain,
        "mode": result.execution_mode,
        "dataset": result.dataset,
        "evaluation_split": result.evaluation_split,
        "source": f"sentrix_ml evaluation ({result.run_type})",
        "metrics": metrics,
        "sample_count": result.sample_count,
        "run_type": result.run_type,
    }
