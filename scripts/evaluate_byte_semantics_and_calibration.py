#!/usr/bin/env python3
"""SENTRi-X Feature Equivalence, Byte Semantics, and Calibration Evaluator.

Addresses Chapter 5 Recommendation #2:
- Per-package live byte-semantics validation (L2/L3/L4 bounds and scaler z-score drift).
- Fusion-weight sensitivity sweep (w_rf in [0.0, 1.0]) for F1, ROC-AUC, Brier score.
- Comprehensive probability calibration evaluation (ECE, MCE, Brier score, reliability curves).

Usage:
    python scripts/evaluate_byte_semantics_and_calibration.py [--output results.json]
"""

import os
import sys
import json
import argparse
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    brier_score_loss, log_loss, f1_score, roc_auc_score,
    precision_score, recall_score, confusion_matrix
)
from sklearn.calibration import calibration_curve

# Ensure repository root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import joblib
from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES

CANDIDATES = {
    "omni": ROOT_DIR / "models" / "candidates" / "omni_v2",
    "ton_iot": ROOT_DIR / "models" / "candidates" / "ton_iot_v2",
    "bot_iot": ROOT_DIR / "models" / "candidates" / "bot_iot_v2",
    "cic_ids2017": ROOT_DIR / "models" / "candidates" / "cic_ids2017_v2",
}

BYTE_PACKET_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "missed_bytes",
    "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes"
]


def compute_ece_mce(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> tuple[float, float, list[dict]]:
    """Compute Expected Calibration Error (ECE), Maximum Calibration Error (MCE), and bin details."""
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    bin_assignments = np.digitize(y_prob, bin_edges) - 1
    bin_assignments = np.clip(bin_assignments, 0, n_bins - 1)

    ece = 0.0
    mce = 0.0
    bins = []
    n_total = len(y_true)

    for b in range(n_bins):
        mask = bin_assignments == b
        count = int(np.sum(mask))
        if count > 0:
            bin_acc = float(np.mean(y_true[mask]))
            bin_conf = float(np.mean(y_prob[mask]))
            diff = abs(bin_acc - bin_conf)
            weight = count / n_total
            ece += weight * diff
            mce = max(mce, diff)
            bins.append({
                "bin": b,
                "range": [round(float(bin_edges[b]), 2), round(float(bin_edges[b + 1]), 2)],
                "count": count,
                "accuracy": round(bin_acc, 5),
                "confidence": round(bin_conf, 5),
                "error": round(diff, 5)
            })
        else:
            bins.append({
                "bin": b,
                "range": [round(float(bin_edges[b]), 2), round(float(bin_edges[b + 1]), 2)],
                "count": 0,
                "accuracy": None,
                "confidence": None,
                "error": 0.0
            })

    return float(ece), float(mce), bins


def validate_package_byte_semantics(candidate_path: Path) -> dict:
    """Analyze the scaler parameters for byte and packet features and compute z-score bounds."""
    pipe_path = candidate_path / "pipeline.joblib"
    if not pipe_path.exists():
        return {"error": f"Missing pipeline at {pipe_path}"}

    pipe = joblib.load(pipe_path)
    scaler = pipe.scaler
    res = {}

    for feat in BYTE_PACKET_FEATURES:
        idx = EXPECTED_FEATURES.index(feat)
        mean_val = float(scaler.mean_[idx])
        scale_val = float(scaler.scale_[idx])
        var_val = float(scaler.var_[idx])
        
        # Test simulated live packet scenarios:
        # e.g., 64-byte TCP SYN packet, 1500-byte full MTU frame, 0-byte flow
        z_syn = (64.0 - mean_val) / scale_val if scale_val > 0 else 0.0
        z_mtu = (1500.0 - mean_val) / scale_val if scale_val > 0 else 0.0
        z_zero = (0.0 - mean_val) / scale_val if scale_val > 0 else 0.0

        res[feat] = {
            "mean": round(mean_val, 4),
            "std": round(scale_val, 4),
            "variance": round(var_val, 4),
            "is_zero_imputed_in_training": bool(mean_val == 0.0 and scale_val == 1.0),
            "z_score_at_zero": round(float(z_zero), 4),
            "z_score_at_64b": round(float(z_syn), 4),
            "z_score_at_1500b": round(float(z_mtu), 4),
        }
    return res


def evaluate_candidate(candidate_name: str, candidate_path: Path) -> dict:
    """Run byte semantics, fusion sweep, and calibration evaluation on a candidate package."""
    byte_semantics = validate_package_byte_semantics(candidate_path)
    
    evidence_path = candidate_path / "prediction_evidence.csv"
    if not evidence_path.exists():
        return {"byte_semantics": byte_semantics, "error": f"Missing {evidence_path}"}

    df = pd.read_csv(evidence_path)
    y_true = df["y_true"].values
    p_rf = df["p_rf"].values
    p_cnn = df["p_cnn"].values
    p_hybrid = df["p_hybrid"].values

    # Mode metrics
    ece_rf, mce_rf, bins_rf = compute_ece_mce(y_true, p_rf)
    ece_cnn, mce_cnn, bins_cnn = compute_ece_mce(y_true, p_cnn)
    ece_hyb, mce_hyb, bins_hyb = compute_ece_mce(y_true, p_hybrid)

    brier_rf = float(brier_score_loss(y_true, p_rf))
    brier_cnn = float(brier_score_loss(y_true, p_cnn))
    brier_hyb = float(brier_score_loss(y_true, p_hybrid))

    f1_rf = float(f1_score(y_true, p_rf >= 0.5))
    f1_cnn = float(f1_score(y_true, p_cnn >= 0.5))
    f1_hyb = float(f1_score(y_true, p_hybrid >= 0.5))

    auc_rf = float(roc_auc_score(y_true, p_rf))
    auc_cnn = float(roc_auc_score(y_true, p_cnn))
    auc_hyb = float(roc_auc_score(y_true, p_hybrid))

    # Fusion sweep w_rf from 0.0 to 1.0
    sweep = []
    best_f1 = -1.0
    best_w = 0.5
    for w in np.linspace(0.0, 1.0, 21):
        w_float = round(float(w), 2)
        p_fused = w_float * p_rf + (1.0 - w_float) * p_cnn
        pred_fused = (p_fused >= 0.5).astype(int)
        f1_val = float(f1_score(y_true, pred_fused))
        brier_val = float(brier_score_loss(y_true, p_fused))
        auc_val = float(roc_auc_score(y_true, p_fused))
        ece_val, mce_val, _ = compute_ece_mce(y_true, p_fused)

        sweep.append({
            "w_rf": w_float,
            "f1": round(f1_val, 5),
            "brier": round(brier_val, 5),
            "roc_auc": round(auc_val, 5),
            "ece": round(ece_val, 5),
            "mce": round(mce_val, 5),
        })
        if f1_val > best_f1:
            best_f1 = f1_val
            best_w = w_float

    return {
        "candidate": candidate_name,
        "n_samples": len(y_true),
        "attack_prevalence": round(float(np.mean(y_true)), 5),
        "byte_semantics": byte_semantics,
        "modes": {
            "rf": {"f1": round(f1_rf, 5), "roc_auc": round(auc_rf, 5), "brier": round(brier_rf, 5), "ece": round(ece_rf, 5), "mce": round(mce_rf, 5)},
            "cnn": {"f1": round(f1_cnn, 5), "roc_auc": round(auc_cnn, 5), "brier": round(brier_cnn, 5), "ece": round(ece_cnn, 5), "mce": round(mce_cnn, 5)},
            "hybrid_equal": {"f1": round(f1_hyb), "roc_auc": round(auc_hyb, 5), "brier": round(brier_hyb, 5), "ece": round(ece_hyb, 5), "mce": round(mce_hyb, 5)},
        },
        "optimal_fusion": {
            "best_w_rf": best_w,
            "best_f1": round(best_f1, 5),
            "f1_gain_over_equal_hybrid": round(best_f1 - f1_hyb, 5),
        },
        "fusion_sweep": sweep,
        "calibration_bins": {
            "rf": bins_rf,
            "cnn": bins_cnn,
            "hybrid": bins_hyb,
        }
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/feature_equivalence_and_calibration.json", help="Path to save evaluation JSON")
    args = parser.parse_args()

    results = {}
    print("Evaluating Chapter 5 Recommendation #2: Byte Semantics, Fusion Weights, and Calibration...")

    for name, path in CANDIDATES.items():
        print(f"-> Processing candidate: {name} ({path})")
        results[name] = evaluate_candidate(name, path)

    out_path = ROOT_DIR / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Successfully saved evaluation report to {out_path}")


if __name__ == "__main__":
    main()
