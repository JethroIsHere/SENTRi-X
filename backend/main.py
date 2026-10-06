import os
import sys
from pathlib import Path
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Literal
from threading import RLock
from uuid import uuid4
from datetime import datetime, timezone
import pandas as pd
import time
import asyncio
import joblib
import psutil
import numpy as np
import json
import importlib
from database import (
    init_db,
    insert_network_flow,
    insert_alert,
    get_all_alerts,
    clear_all_alerts,
    get_database_stats, get_recent_flows, get_device_summaries, get_alert_counts,
    load_settings, save_settings, utc_now,
    get_monitored_devices, add_monitored_device, remove_monitored_device,
    get_whitelisted_destinations, add_whitelisted_destination,
    remove_whitelisted_destination, is_destination_whitelisted,
    get_whitelisted_domains, add_whitelisted_domain,
    remove_whitelisted_domain, is_domain_whitelisted,
    get_whitelisted_device_ports, add_whitelisted_device_port,
    remove_whitelisted_device_port, is_device_port_whitelisted
)

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from narrative import generate_attack_narrative
from sentrix_ml.preprocessing import PreprocessingPipeline, build_feature_row
from sentrix_ml.inference import run_single_inference
from sentrix_ml.packaging import validate_package, ModelManifest, PackageValidationError, file_sha256
from sentrix_ml.evaluation import EvaluationResult, format_metrics_for_api
from sentrix_ml.xai import create_lime_explainer, explain_with_lime, reference_shap_explanation, XAIProvenance

app = FastAPI(title="SENTRi-X Backend API", description="Hybrid & Explainable NIDS Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Hardware heartbeat/liveness timeout in seconds.
HARDWARE_LIVE_TIMEOUT = 10.0

# Active Model Refs Object
class ActiveEngine:
    def __init__(self):
        self.rf_model = None
        self.cnn_model = None
        self.pipeline = None
        self.scaler = None
        self.manifest = None
        self.package_dir = None
        self.df = None
        self.malicious_pool = None
        self.attack_queue = []
        self.current_dataset = "omni"
        self.current_model = "omni"
        self.execution_mode = "hybrid"  # "hybrid" | "rf" | "cnn"
        self.data_source = "live_hardware"
        self.last_hardware_ping = 0.0
        self.row_idx = 0
        self.last_flow_received = 0.0
        self.last_error = None
        self.switching = False


# Logical model names -> committed candidate package directories.
# The validated packages are versioned (omni_v2, ...); the backend and UI
# use the logical names. Resolved at load time so fresh clones work.
PACKAGE_ALIASES = {
    "omni": "omni_v2",
    "ton_iot": "ton_iot_v2",
    "bot_iot": "bot_iot_v2",
    "cic_ids2017": "cic_ids2017_v2",
}


def resolve_package_dir(target: str) -> str:
    """Map a logical model name to its candidate package directory.

    Prefers an explicitly activated package at models/candidates/<target>
    (written by the activation/rollback workflow); falls back to the
    versioned committed package (models/candidates/<target>_v2) for fresh
    clones where no manual activation exists.
    """
    base = os.path.join(os.path.dirname(__file__), "..", "models", "candidates")
    direct = os.path.join(base, target)
    if os.path.exists(os.path.join(direct, "manifest.json")):
        return direct
    actual = PACKAGE_ALIASES.get(target, target)
    return os.path.join(base, actual)

engine = ActiveEngine()
engine_lock = RLock()
# Default alert threshold set to the F1-optimal operating point from the
# threshold sweep on 17,842 held-out Omni flows (2026-10-06):
# thr=0.50 -> precision 0.9985, recall 0.9618, F1 0.9798 (best F1).
# Adjustable per deployment via PUT /api/settings (range 0.50-0.99).
settings = {"active_alerting": True, "alert_threshold": 0.50}

# Explainability artifacts container
explainability = {
    "shap_values": None,
    "X_sample": None,
    "ripper_rules": None,
    "ripper_fidelity": None,
    "ripper_fidelity_note": None,
    "lime_explainer": None,
    "lime_feature_names": None,
    "shap_explainer": None,
}

system_status = {
    "processed_flows": 0, "simulated_events": 0, "inference_errors": 0,
    "counter_epoch": str(uuid4()), "started_at": utc_now(), "ingest_error": None,
    "chart_data": [], "latest_shap": [], "latest_lime": [],
}


def classify_threat_level(confidence: float) -> str:
    if confidence >= 0.98:
        return "Critical"
    if confidence >= 0.95:
        return "High"
    if confidence >= 0.90:
        return "Medium"
    return "Low"


def initialize_lime_explainer():
    """Initialize a reusable LIME explainer from package background data using sentrix_ml.xai."""
    X_sample_df = explainability.get("X_sample")
    if X_sample_df is None or len(X_sample_df) == 0:
        explainability["lime_explainer"] = None
        explainability["lime_feature_names"] = None
        return

    try:
        X_numeric = X_sample_df.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        X_numeric = X_numeric.reindex(columns=EXPECTED_FEATURES, fill_value=0.0)
        feature_names = list(X_numeric.columns)
        explainability["lime_feature_names"] = feature_names
        explainability["lime_explainer"] = create_lime_explainer(
            background_data=X_numeric,
            feature_names=feature_names,
        )
        if explainability["lime_explainer"] is not None:
            print(f"LIME explainer initialized with {len(feature_names)} features")
    except Exception as e:
        explainability["lime_explainer"] = None
        explainability["lime_feature_names"] = None
        print(f"Failed to initialize LIME explainer: {e}")


def generate_xai_background(n_samples: int = 2000) -> pd.DataFrame | None:
    """Generate synthetic background data from the fitted scaler's statistics.

    Samples numeric features from Normal(mean, scale), clipped to valid
    ranges. One-hot groups are sampled as VALID mutually-exclusive choices
    (a flow is TCP xor UDP xor other; exactly one conn_state or none) using
    the scaler means as category probabilities -- independent Bernoulli
    sampling produced impossible flows (TCP+UDP, multiple states).
    Used for LIME background and RIPPER surrogate training when no stored
    background data exists. Returns a DataFrame in RAW feature space
    (pre-scaler), or None if the scaler/RF model is unavailable.
    """
    if engine.scaler is None or engine.rf_model is None:
        return None
    try:
        from sentrix_ml.schema import (
            EXPECTED_FEATURES, PROTO_FEATURE_NAMES, CONN_STATE_FEATURE_NAMES,
        )
        means = np.asarray(engine.scaler.mean_, dtype=float)
        scales = np.asarray(engine.scaler.scale_, dtype=float)
        scales = np.where(scales <= 0, 1.0, scales)
        rng = np.random.default_rng(42)
        cols = list(EXPECTED_FEATURES)
        data = {}
        binary_feats = set(PROTO_FEATURE_NAMES) | set(CONN_STATE_FEATURE_NAMES)
        for i, feat in enumerate(cols):
            if feat in binary_feats:
                continue  # handled as mutually-exclusive groups below
            vals = rng.normal(means[i], scales[i], size=n_samples)
            data[feat] = np.clip(vals, 0.0, None)

        # Protocol: exactly one of TCP / UDP / other (neither flag set)
        p_tcp = float(np.clip(means[cols.index("proto_tcp")], 0.0, 1.0))
        p_udp = float(np.clip(means[cols.index("proto_udp")], 0.0, 1.0))
        p_other = max(0.0, 1.0 - p_tcp - p_udp)
        tot = p_tcp + p_udp + p_other or 1.0
        proto = rng.choice(
            ["tcp", "udp", "other"], size=n_samples,
            p=[p_tcp / tot, p_udp / tot, p_other / tot],
        )
        data["proto_tcp"] = (proto == "tcp").astype(float)
        data["proto_udp"] = (proto == "udp").astype(float)

        # Connection state: exactly one of the 12 states, or none
        cs_probs = np.array(
            [float(np.clip(means[cols.index(f)], 0.0, 1.0)) for f in CONN_STATE_FEATURE_NAMES]
        )
        p_none = max(0.0, 1.0 - cs_probs.sum())
        probs = np.append(cs_probs, p_none)
        probs = probs / (probs.sum() or 1.0)
        cs_choice = rng.choice(len(probs), size=n_samples, p=probs)
        for j, feat in enumerate(CONN_STATE_FEATURE_NAMES):
            data[feat] = (cs_choice == j).astype(float)
        # (cs_choice == 12 means "none" -- all flags stay 0)

        df = pd.DataFrame(data, columns=cols)
        # Sanity: no row may have both proto flags or >1 conn_state
        assert ((df["proto_tcp"] + df["proto_udp"]) <= 1).all()
        assert (df[list(CONN_STATE_FEATURE_NAMES)].sum(axis=1) <= 1).all()
        return df
    except Exception as e:
        print(f"Failed to generate XAI background data: {e}")
        return None


def initialize_xai_artifacts():
    """Wire up runtime XAI artifacts after a package is activated.

    Populates the explainability slots from the active model:
    - X_sample: synthetic background (raw feature space) for LIME/SHAP.
    - lime_explainer: LIME TabularExplainer (via initialize_lime_explainer).
    - ripper_rules: IF-THEN rules from a RIPPER surrogate trained on
      RF-labeled synthetic data (wittgenstein).
    - shap_explainer: shap.TreeExplainer for per-flow attributions.
    All steps are best-effort; failures leave the slot empty with a log.
    """
    explainability["X_sample"] = None
    explainability["shap_values"] = None
    explainability["ripper_rules"] = None
    explainability["ripper_fidelity"] = None
    explainability["ripper_fidelity_note"] = None
    explainability["lime_explainer"] = None
    explainability["lime_feature_names"] = None
    explainability["shap_explainer"] = None

    if engine.rf_model is None or engine.scaler is None:
        print("XAI init skipped: no active RF model/scaler.")
        return

    # 1. Background data (raw space)
    bg = generate_xai_background()
    if bg is None or len(bg) == 0:
        print("XAI init: background generation failed.")
        return
    explainability["X_sample"] = bg

    # 2. LIME
    try:
        initialize_lime_explainer()
    except Exception as e:
        print(f"XAI init: LIME setup failed: {e}")

    # 3. SHAP TreeExplainer (per-flow attributions)
    try:
        import shap
        explainability["shap_explainer"] = shap.TreeExplainer(engine.rf_model)
        print("SHAP TreeExplainer initialized.")
    except Exception as e:
        explainability["shap_explainer"] = None
        print(f"XAI init: SHAP setup failed (install 'shap'): {e}")

    # 4. RIPPER surrogate rules (wittgenstein) trained on RF-labeled background.
    #
    # LIMITATION (documented for expert review): the background rows are
    # SYNTHETIC, sampled from the fitted scaler's per-feature statistics --
    # not representative training rows. The committed packages do not include
    # a training sample. Future package versions should bundle a held-out
    # training sample for faithful surrogate training and evaluation.
    # Within that constraint, fidelity is measured honestly: RIPPER trains on
    # one split and is evaluated on a SEPARATE held-out split, so the score
    # reflects generalization to unseen synthetic rows, not training-set
    # memorization.
    try:
        import wittgenstein as lw
        # Split: 75% for RIPPER training, 25% held-out for fidelity
        n_bg = len(bg)
        n_train = int(n_bg * 0.75)
        bg_train = bg.iloc[:n_train].reset_index(drop=True)
        bg_heldout = bg.iloc[n_train:].reset_index(drop=True)

        X_train_scaled = engine.scaler.transform(bg_train.to_numpy(dtype=float))
        y_train = engine.rf_model.predict(X_train_scaled)
        clf = lw.RIPPER()
        clf.fit(bg_train, y_train)
        rules_text = str(clf.ruleset_) if hasattr(clf, "ruleset_") else ""
        if not rules_text:
            # Fallback: render rules manually
            rules_text = "\n".join(str(r) for r in getattr(clf, "ruleset_", []))
        explainability["ripper_rules"] = rules_text or "No rules learned."
        n_rules = len(getattr(clf, "ruleset_", []))

        # Fidelity on HELD-OUT rows (not training rows)
        fidelity = None
        fidelity_note = ""
        try:
            X_held_scaled = engine.scaler.transform(bg_heldout.to_numpy(dtype=float))
            y_held_rf = engine.rf_model.predict(X_held_scaled)
            y_held_rip = clf.predict(bg_heldout)
            fidelity = float(np.mean(
                np.asarray(y_held_rip).ravel() == np.asarray(y_held_rf).ravel()
            ))
            fidelity_note = (
                f"Agreement on {len(bg_heldout)} held-out synthetic rows "
                f"(separate from {len(bg_train)} training rows)."
            )
        except Exception as e:
            # JSON null, not NaN: NaN is invalid in standard JSON.
            fidelity = None
            fidelity_note = f"Fidelity measurement failed: {e}"
            print(f"RIPPER fidelity measurement failed: {e}")
        explainability["ripper_fidelity"] = fidelity
        explainability["ripper_fidelity_note"] = fidelity_note
        fid_str = f"{fidelity:.3f}" if fidelity is not None else "unavailable"
        print(f"RIPPER surrogate trained: {n_rules} rules, held-out fidelity vs RF: {fid_str}.")
    except Exception as e:
        explainability["ripper_rules"] = None
        explainability["ripper_fidelity"] = None
        explainability["ripper_fidelity_note"] = f"RIPPER training failed: {e}"
        print(f"XAI init: RIPPER setup failed (install 'wittgenstein'): {e}")


def compute_shap_explanation(inference_df: pd.DataFrame) -> dict:
    """Compute per-flow SHAP attributions with the runtime TreeExplainer.

    Returns real SHAP values for the current flow (attack class), not the
    global-importance fallback. Falls back to reference_shap_explanation
    only if the TreeExplainer is unavailable.
    """
    explainer = explainability.get("shap_explainer")
    if explainer is not None and engine.rf_model is not None:
        try:
            from sentrix_ml.schema import EXPECTED_FEATURES, ATTACK_CLASS_INDEX
            row = inference_df.reindex(columns=list(EXPECTED_FEATURES), fill_value=0.0)
            row = row.apply(pd.to_numeric, errors="coerce").fillna(0.0)
            scaled = engine.scaler.transform(row.to_numpy(dtype=float)) if engine.scaler else row.to_numpy(dtype=float)
            sv = explainer.shap_values(scaled)
            # Select attack-class values BEFORE ranking. Newer shap returns
            # a single (samples, features, classes) array; older returns a
            # list of (samples, features) per class.
            if isinstance(sv, list):
                arr = np.asarray(sv[ATTACK_CLASS_INDEX] if ATTACK_CLASS_INDEX < len(sv) else sv[-1])
            else:
                arr = np.asarray(sv)
                if arr.ndim == 3:
                    # (samples, features, classes) -> attack class slice
                    if arr.shape[2] <= ATTACK_CLASS_INDEX:
                        raise ValueError(f"SHAP classes dim {arr.shape[2]} < attack index")
                    arr = arr[:, :, ATTACK_CLASS_INDEX]
            vec = arr.reshape(-1)
            names = list(EXPECTED_FEATURES)
            if vec.shape[0] != len(names):
                raise ValueError(f"SHAP vector length {vec.shape[0]} != {len(names)} features")
            top = np.argsort(np.abs(vec))[-5:][::-1]
            return {
                "values": [{"f": names[i], "v": round(float(vec[i]), 4)} for i in top],
                "method": "tree_shap_per_flow",
                "target_class": ATTACK_CLASS_INDEX,
            }
        except Exception as e:
            print(f"SHAP computation failed, trying reference: {e}")
    # Fallback to reference lookup
    features, meta = reference_explanation(inference_df)
    return {"values": features, "method": meta.get("shap_method", "unavailable"),
            "target_class": meta.get("shap_target_class")}


def compute_lime_explanation_for_packet(inference_df: pd.DataFrame):
    """Compute top LIME contributors for one inference packet using sentrix_ml.xai."""
    explainer = explainability.get("lime_explainer")
    feature_names = explainability.get("lime_feature_names")

    if explainer is None or not feature_names or engine.rf_model is None:
        return {"values": [], "target_class": None, "method": "unavailable"}

    try:
        row_df = inference_df.reindex(columns=feature_names, fill_value=0.0)
        row_df = row_df.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        row_arr = row_df.to_numpy(dtype=float)[0]

        def predict_fn(samples_np):
            samples_df = pd.DataFrame(samples_np, columns=feature_names).fillna(0.0)
            if engine.pipeline is not None:
                model_input = engine.pipeline.transform(samples_df)
            elif engine.scaler is not None:
                model_input = engine.scaler.transform(samples_df)
            else:
                model_input = samples_df.to_numpy(dtype=float)

            if hasattr(engine.rf_model, "predict_proba"):
                probabilities = engine.rf_model.predict_proba(model_input)
                classes = list(getattr(engine.rf_model, 'classes_', [0, 1]))
                if 0 not in classes or 1 not in classes:
                    raise ValueError('LIME requires benign class 0 and attack class 1.')
                return probabilities[:, [classes.index(0), classes.index(1)]]

            preds = engine.rf_model.predict(model_input)
            preds = np.array(preds, dtype=float).reshape(-1, 1)
            return np.hstack([1 - preds, preds])

        res = explain_with_lime(explainer, row_arr, predict_fn, num_features=3)
        return {"values": res.features, "target_class": res.target_class, "method": res.method}
    except Exception as e:
        print(f"Failed to compute LIME explanation: {e}")
        return {"values": [], "target_class": None, "method": "unavailable"}


def update_core_model_label():
    """Update human-readable core model status string."""
    domain_label = engine.current_model.upper()
    if engine.current_model == "omni":
        domain_label = "OMNI (GLOBAL)"
    elif engine.current_model == "ton_iot":
        domain_label = "ToN-IoT"
    elif engine.current_model == "bot_iot":
        domain_label = "BoT-IoT"
    elif engine.current_model == "cic_ids2017":
        domain_label = "CIC-IDS2017"

    mode_label = "Hybrid Ensemble (RF+CNN)"
    if engine.execution_mode == "rf":
        mode_label = "Random Forest Only"
    elif engine.execution_mode == "cnn":
        mode_label = "1D CNN Only"

    system_status["core_model"] = f"{mode_label} - {domain_label}"
    system_status["current_dataset"] = engine.current_dataset
    system_status["current_model"] = engine.current_model
    system_status["execution_mode"] = engine.execution_mode
    system_status["data_source"] = engine.data_source
    system_status["rf_online"] = (engine.rf_model is not None) and (engine.execution_mode in ["rf", "hybrid"])
    system_status["cnn_online"] = (engine.cnn_model is not None) and (engine.execution_mode in ["cnn", "hybrid"])


def load_models_and_data(target="omni", dataset="omni", is_startup=False, candidates_dir=None):
    """Stage and validate candidate model package before replacing engine state atomically.
    Never mutates engine state on failure.
    Does NOT fall back to unvalidated legacy files.
    """
    print(f"Loading target '{target}' models and dataset '{dataset}'...")
    if candidates_dir is None:
        candidates_dir = resolve_package_dir(target)
    manifest_path = os.path.join(candidates_dir, "manifest.json")

    if not os.path.exists(manifest_path):
        msg = f"No candidate package found for '{target}' in {candidates_dir}."
        if is_startup:
            print(f"Startup: {msg}")
            engine.rf_model = None
            engine.cnn_model = None
            engine.pipeline = None
            engine.scaler = None
            engine.manifest = None
            engine.package_dir = None
            engine.current_dataset = dataset
            engine.current_model = target
            engine.last_error = msg
            system_status["rf_online"] = False
            system_status["cnn_online"] = False
            update_core_model_label()
            return
        raise ValueError(msg)

    # Stage candidate in local variables before modifying engine
    try:
        print(f"Found candidate package for '{target}' in {candidates_dir}. Validating manifest...")
        manifest = validate_package(candidates_dir, strict_deployable=True, target_domain=target)

        rf_path = os.path.join(candidates_dir, manifest.rf_file)
        staged_rf = joblib.load(rf_path)

        cnn_path = os.path.join(candidates_dir, manifest.cnn_file)
        staged_cnn = None
        try:
            from tensorflow.keras.models import load_model
            staged_cnn = load_model(cnn_path, compile=False)
        except Exception as e:
            print(f"CNN load warning in {target}: {e}")

        pipe_path = os.path.join(candidates_dir, manifest.preprocessor_file)
        staged_pipeline = PreprocessingPipeline.load(pipe_path)
        staged_scaler = staged_pipeline.scaler

        # Validate preprocessing pipeline is fitted unconditionally
        if not staged_pipeline.is_fitted:
            raise PackageValidationError("Preprocessing pipeline is not fitted.")
        if staged_rf is None:
            raise PackageValidationError("Random Forest model is missing from candidate package.")

        # Validate inference execution
        dummy_test = np.zeros((1, NUM_FEATURES), dtype=float)
        staged_scaled = staged_pipeline.transform(dummy_test)
        run_single_inference(staged_scaled, rf_model=staged_rf, cnn_model=staged_cnn, mode="hybrid")

        # Atomic commit to engine state
        engine.manifest = manifest
        engine.package_dir = candidates_dir
        engine.rf_model = staged_rf
        engine.cnn_model = staged_cnn
        engine.pipeline = staged_pipeline
        engine.scaler = staged_scaler
        engine.current_dataset = dataset
        engine.current_model = target
        engine.last_error = None
        system_status["rf_online"] = staged_rf is not None
        system_status["cnn_online"] = staged_cnn is not None
        update_core_model_label()
        print(f"Candidate package '{target}' successfully validated and activated!")
        # Wire up runtime XAI artifacts from the newly activated model
        try:
            initialize_xai_artifacts()
        except Exception as e:
            print(f"XAI artifact init failed (non-fatal): {e}")
    except Exception as exc:
        print(f"Failed to load candidate package for '{target}': {exc}")
        if is_startup:
            engine.rf_model = None
            engine.cnn_model = None
            engine.pipeline = None
            engine.scaler = None
            engine.manifest = None
            engine.package_dir = None
            engine.current_dataset = dataset
            engine.current_model = target
            engine.last_error = f"Package validation failed: {exc}"
            system_status["rf_online"] = False
            system_status["cnn_online"] = False
            update_core_model_label()
            return
        raise


def prepare_feature_dataframe(packet_data):
    """Aligns dictionary or Series packet data into the canonical 28-feature DataFrame.
    Uses sentrix_ml.preprocessing.build_feature_row for canonical encoding.
    """
    return build_feature_row(packet_data)



def run_inference(inference_df):
    """Run inference with explicit pipeline scaling and validation.
    A failed model or missing scaler is reported as an error; it never silently
    falls back to unscaled inference or benign output.
    """
    if engine.pipeline is not None:
        scaled = engine.pipeline.transform(inference_df)
    elif engine.scaler is not None:
        scaled = engine.scaler.transform(inference_df)
    else:
        raise RuntimeError("Model preprocessing pipeline/scaler is unavailable. Unscaled inference is rejected.")

    mode = engine.execution_mode
    if mode in ('rf', 'hybrid') and engine.rf_model is None:
        raise RuntimeError('The selected Random Forest is unavailable.')
    if mode in ('cnn', 'hybrid') and engine.cnn_model is None:
        raise RuntimeError('The selected CNN is unavailable.')

    res = run_single_inference(
        scaled,
        rf_model=engine.rf_model,
        cnn_model=engine.cnn_model,
        mode=mode,
    )
    return res.prediction, res.confidence, res.p_rf, res.p_cnn



def reference_explanation(inference_df):
    """Expose provenance for reference explanations with active model domain validation."""
    active_hash = engine.manifest.rf_hash if engine.manifest else None
    active_domain = engine.current_model
    prov = explainability.get("shap_provenance")
    res = reference_shap_explanation(
        inference_df,
        X_sample=explainability.get("X_sample"),
        shap_values=explainability.get("shap_values"),
        rf_model=engine.rf_model,
        provenance=prov,
        active_domain=active_domain,
        active_model_hash=active_hash,
    )
    meta = {
        "shap_method": res.method,
        "shap_model": res.model or "unknown",
        "shap_target_class": res.target_class,
        "reason": res.reason,
    }
    return res.features, meta


def record_threat_alert(packet_data, inference_df, confidence, source, flow_id=None):
    shap_res = compute_shap_explanation(inference_df)
    features = shap_res["values"]
    metadata = {
        "shap_method": shap_res["method"],
        "shap_model": "random_forest",
        "shap_target_class": shap_res["target_class"],
        "reason": "",
    }
    # Plain-English attack narrative for thesis evaluation and operator review.
    # Generated from flow fields + SHAP-ranked features; describes observed
    # behavior, not assumed intent.
    try:
        narrative = generate_attack_narrative(
            flow=packet_data,
            shap_values=features if isinstance(features, list) else [],
            feature_names=list(inference_df.columns) if hasattr(inference_df, 'columns') else [],
            confidence=confidence,
            model_type=engine.current_model,
        )
        metadata["reason"] = narrative
    except Exception:
        metadata["reason"] = ""  # Narrative is supplementary; never break alert recording.
    lime = compute_lime_explanation_for_packet(inference_df)
    metadata.update(lime_method='local_rf_lime' if lime['values'] else 'unavailable',
                    lime_model='random_forest', lime_target_class=lime['target_class'])
    # Live inference is binary. Dataset labels are contextual labels, not model subtype predictions.
    label = 'Malicious Flow Anomaly'
    if source == 'simulation':
        for key in ('type', 'Label', 'label'):
            value = packet_data.get(key)
            if value is not None and str(value).lower() not in ('normal', 'benign', '0', '0.0', 'nan', '1', '1.0'):
                label = str(value)
                break
    src = packet_data.get('src_ip') or packet_data.get('src') or 'unknown'
    dst = packet_data.get('dst_ip') or packet_data.get('dst') or 'unknown'
    level = classify_threat_level(confidence)
    alert = dict(id=str(uuid4()), timestamp=utc_now(), source_ip=str(src), target_ip=str(dst),
                 dest_ip=str(dst), attack_type=label, confidence=confidence, threat_level=level,
                 status='Recorded alert', model_type=engine.current_model,
                 execution_mode=engine.execution_mode, data_source=source, flow_id=flow_id,
                 sensor_id=packet_data.get('sensor_id'), device_name=packet_data.get('device_name'),
                 device_mac=packet_data.get('device_mac'), shap_values=features,
                 lime_values=lime['values'], explanation_meta=metadata,
                 attack_type_source='dataset_label' if label != 'Malicious Flow Anomaly' else 'binary_classifier')
    insert_alert(alert)
    return alert


class SettingsRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    active_alerting: bool
    alert_threshold: float = Field(ge=0.5, le=0.99)


class SwitchRequest(BaseModel):
    model_type: Literal['omni', 'ton_iot', 'bot_iot', 'cic_ids2017'] = 'omni'
    dataset: Optional[Literal['omni', 'ton_iot', 'bot_iot', 'cic_ids2017']] = None
    mode: Literal['hybrid', 'rf', 'cnn'] = 'hybrid'


class ClearRequest(BaseModel):
    scope: Literal['simulation', 'all'] = 'simulation'


class AttackRequest(BaseModel):
    type: str = 'DDoS'
    intensity: int = Field(default=5, ge=1, le=100)


def hardware_live():
    return engine.last_hardware_ping > 0 and time.time() - engine.last_hardware_ping < HARDWARE_LIVE_TIMEOUT


def alert_allowed(prediction, confidence, dst_ip=None, sni=None, mac=None, dst_port=None):
    if not (settings['active_alerting'] and prediction == 1 and confidence > settings['alert_threshold']):
        return False
    # Suppress alerts for whitelisted destination IPs (known IoT cloud endpoints)
    if dst_ip and is_destination_whitelisted(dst_ip):
        return False
    # Suppress alerts for whitelisted domains (SNI-based, e.g. *.tuyaeu.com)
    if sni and is_domain_whitelisted(sni):
        return False
    # Suppress alerts for whitelisted MAC+Port (e.g. smart plug on port 443/8883)
    if mac and dst_port and is_device_port_whitelisted(mac, dst_port):
        return False
    return True


@app.on_event('startup')
async def startup_event():
    init_db()
    stored = load_settings(settings)
    settings.update(SettingsRequest(**stored).model_dump())
    load_models_and_data('omni', 'omni', is_startup=True)
    # XAI artifacts (LIME/SHAP/RIPPER) are initialized inside
    # load_models_and_data via initialize_xai_artifacts().


@app.on_event('shutdown')
async def shutdown_event():
    pass


@app.get('/')
def read_root():
    return {'message': 'SENTRi-X API', 'current_model': engine.current_model,
            'execution_mode': engine.execution_mode, 'api_version': 2}


@app.get('/api/status')
def get_status():
    live = hardware_live()
    engine.data_source = 'live_hardware'
    update_core_model_label()
    counts = get_alert_counts()
    if live:
        node_status = 'Pi connected'
    elif engine.last_hardware_ping > 0:
        node_status = 'Pi disconnected'
    else:
        node_status = 'Waiting for Pi'
    result = dict(system_status)
    result.update(api_version=2, is_hardware_live=live,
                  node_status=node_status,
                  data_source=engine.data_source, threats_detected=sum(counts.values()), alert_counts=counts,
                  last_flow_at=(datetime.fromtimestamp(engine.last_flow_received, timezone.utc).isoformat()
                                if engine.last_flow_received else None),
                  last_heartbeat_at=(datetime.fromtimestamp(engine.last_hardware_ping, timezone.utc).isoformat()
                                     if engine.last_hardware_ping > 0 else None),
                  settings=dict(settings), classification_threshold=0.5,
                  engine_error=engine.last_error, switching=engine.switching,
                  simulation_active=False)
    try:
        memory = psutil.virtual_memory()
        result.update(cpu_usage=float(psutil.cpu_percent(interval=None)), memory_usage=float(memory.percent),
                      memory_total_bytes=int(memory.total), memory_used_bytes=int(memory.used),
                      cpu_count=psutil.cpu_count(), resource_error=None)
    except Exception as exc:
        result.update(cpu_usage=None, memory_usage=None, memory_total_bytes=None,
                      memory_used_bytes=None, cpu_count=None, resource_error=str(exc))
    return result


@app.get('/api/threat-logs')
def get_threat_logs(limit: int = Query(100, ge=1, le=500),
                    source: Optional[Literal['live_hardware', 'simulation', 'unknown']] = None):
    return {'logs': get_all_alerts(limit, source)}


@app.get('/api/flows')
def get_flows(limit: int = Query(100, ge=1, le=500),
              source: Optional[Literal['live_hardware', 'simulation', 'unknown']] = 'live_hardware'):
    return {'flows': get_recent_flows(limit, source)}


@app.get('/api/devices')
def get_devices():
    return {'devices': get_device_summaries()}


class MonitoredDeviceRequest(BaseModel):
    mac: str
    name: str


@app.get('/api/monitored-devices')
def list_monitored_devices():
    """Dashboard-managed allowlist of device MACs the Pi sensor monitors."""
    return {'devices': get_monitored_devices()}


@app.post('/api/monitored-devices')
def create_monitored_device(request: MonitoredDeviceRequest):
    try:
        add_monitored_device(request.mac, request.name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {'status': 'ok', 'devices': get_monitored_devices()}


@app.delete('/api/monitored-devices/{mac}')
def delete_monitored_device(mac: str):
    if not remove_monitored_device(mac):
        raise HTTPException(404, 'Device not found')
    return {'status': 'ok', 'devices': get_monitored_devices()}


class WhitelistRequest(BaseModel):
    ip: str
    label: str
    reason: str = ''


@app.get('/api/whitelisted-destinations')
def list_whitelisted_destinations():
    """Destination IPs whose flows are classified but never trigger alerts."""
    return {'destinations': get_whitelisted_destinations()}


@app.post('/api/whitelisted-destinations')
def create_whitelisted_destination(request: WhitelistRequest):
    try:
        add_whitelisted_destination(request.ip, request.label, request.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {'status': 'ok', 'destinations': get_whitelisted_destinations()}


@app.delete('/api/whitelisted-destinations/{ip}')
def delete_whitelisted_destination(ip: str):
    if not remove_whitelisted_destination(ip):
        raise HTTPException(404, 'Destination not found')
    return {'status': 'ok', 'destinations': get_whitelisted_destinations()}


class DomainWhitelistRequest(BaseModel):
    domain: str
    label: str
    reason: str = ''


@app.get('/api/whitelisted-domains')
def list_whitelisted_domains():
    """Domains (SNI) whose flows are classified but never trigger alerts."""
    return {'domains': get_whitelisted_domains()}


@app.post('/api/whitelisted-domains')
def create_whitelisted_domain(request: DomainWhitelistRequest):
    try:
        add_whitelisted_domain(request.domain, request.label, request.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {'status': 'ok', 'domains': get_whitelisted_domains()}


@app.delete('/api/whitelisted-domains/{domain}')
def delete_whitelisted_domain(domain: str):
    if not remove_whitelisted_domain(domain):
        raise HTTPException(404, 'Domain not found')
    return {'status': 'ok', 'domains': get_whitelisted_domains()}


class DevicePortWhitelistRequest(BaseModel):
    mac: str
    port: int
    reason: str = ''


@app.get('/api/whitelisted-device-ports')
def list_whitelisted_device_ports():
    """MAC+Port combinations whose flows are classified but never trigger alerts."""
    return {'device_ports': get_whitelisted_device_ports()}


@app.post('/api/whitelisted-device-ports')
def create_whitelisted_device_port(request: DevicePortWhitelistRequest):
    try:
        add_whitelisted_device_port(request.mac, request.port, request.reason)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {'status': 'ok', 'device_ports': get_whitelisted_device_ports()}


@app.delete('/api/whitelisted-device-ports/{mac}/{port}')
def delete_whitelisted_device_port(mac: str, port: int):
    if not remove_whitelisted_device_port(mac, port):
        raise HTTPException(404, 'Combination not found')
    return {'status': 'ok', 'device_ports': get_whitelisted_device_ports()}


@app.get('/api/database/stats')
def get_db_stats():
    return get_database_stats()


@app.get('/api/model-metrics')
def get_model_metrics():
    """Returns validated evaluation metrics for the active engine package and mode.
    Returns available=False if no package, smoke run, missing/tampered evidence,
    or hash mismatch against the active manifest. Legacy unverified metrics are removed.
    """
    if engine.manifest and engine.manifest.evaluation_file and engine.package_dir:
        eval_path = os.path.join(engine.package_dir, engine.manifest.evaluation_file)
        if not os.path.exists(eval_path):
            return {'available': False, 'reason': 'Evaluation metrics file missing on disk.'}
        try:
            disk_hash = file_sha256(eval_path)
            if not engine.manifest.evaluation_hash or disk_hash != engine.manifest.evaluation_hash:
                return {'available': False, 'reason': 'Evaluation file integrity check failed (tampered file or SHA256 mismatch).'}
            eval_res = EvaluationResult.load(eval_path)
            return format_metrics_for_api(eval_res, mode=engine.execution_mode, active_manifest=engine.manifest)
        except Exception as e:
            print(f"Error reading package evaluation metrics: {e}")
            return {'available': False, 'reason': f"Evaluation read error: {e}"}
    return {'available': False, 'reason': 'No validated evaluation evidence for active package'}


@app.get('/api/explainability/ripper')
def get_ripper_rules():
    rules = explainability.get('ripper_rules') or ''
    fidelity = explainability.get('ripper_fidelity')
    fidelity_note = explainability.get('ripper_fidelity_note') or ''
    scope = 'runtime_ripper_surrogate' if rules else 'unavailable'
    # fidelity is None (JSON null) when measurement failed; never NaN.
    return {'rules': rules, 'scope': scope,
            'fidelity_vs_rf': fidelity,
            'fidelity_note': fidelity_note,
            'background': 'synthetic_from_scaler_stats',
            'evaluated_on_live_flow': False,
            'note': 'RIPPER (wittgenstein) surrogate trained on RF-labeled synthetic background at package activation.' if rules else 'RIPPER rules not available; train at package activation (install wittgenstein).'}


@app.get('/api/explainability/sample/{idx}')
def get_explainability_sample(idx: int):
    samples = explainability.get('X_sample')
    stored = explainability.get('shap_values')
    if samples is None or idx < 0 or idx >= len(samples):
        raise HTTPException(404, 'Reference sample unavailable')
    vector = None
    if stored is not None:
        values = np.asarray(stored)
        n, features = len(samples), len(samples.columns)
        if values.ndim == 2 and values.shape == (n, features):
            vector = values[idx]
        elif values.ndim == 3 and values.shape == (2, n, features):
            vector = values[1, idx]
        elif values.ndim == 3 and values.shape == (n, features, 2):
            vector = values[idx, :, 1]
    safe_vector = vector.tolist() if vector is not None and np.all(np.isfinite(vector)) else None
    row = samples.iloc[idx].astype(object).where(pd.notna(samples.iloc[idx]), None).to_dict()
    return {'index': idx, 'sample': row, 'shap': safe_vector, 'scope': 'stored_reference_sample'}


@app.get('/api/settings')
def get_settings():
    return {**settings, 'classification_threshold': 0.5}


@app.put('/api/settings')
def update_settings(request: SettingsRequest):
    with engine_lock:
        values = request.model_dump()
        save_settings(values)
        settings.update(values)
    return get_settings()


@app.post('/api/clear')
def clear_dashboard_data(request: ClearRequest = ClearRequest()):
    with engine_lock:
        clear_all_alerts('simulation' if request.scope == 'simulation' else None)
        engine.attack_queue.clear()
        system_status['simulated_events'] = 0
        if request.scope == 'all':
            system_status['processed_flows'] = 0
            system_status['inference_errors'] = 0
            system_status['counter_epoch'] = str(uuid4())
    return {'status': 'ok', 'scope': request.scope, 'flows_retained': True}


@app.post('/api/switch')
def switch_engine(request: SwitchRequest):
    with engine_lock:
        previous_state = {
            'manifest': engine.manifest,
            'package_dir': engine.package_dir,
            'rf_model': engine.rf_model,
            'cnn_model': engine.cnn_model,
            'pipeline': engine.pipeline,
            'scaler': engine.scaler,
            'current_dataset': engine.current_dataset,
            'current_model': engine.current_model,
            'execution_mode': engine.execution_mode,
            'last_error': engine.last_error,
        }
        previous_rf_online = system_status.get('rf_online', False)
        previous_cnn_online = system_status.get('cnn_online', False)
        engine.switching = True
        try:
            dataset = request.dataset or request.model_type
            if dataset != request.model_type:
                raise ValueError('Model and preprocessing dataset must match.')
            
            need_load = (
                engine.current_model != request.model_type
                or engine.current_dataset != dataset
                or (request.mode in ('rf', 'hybrid') and engine.rf_model is None)
                or (request.mode in ('cnn', 'hybrid') and engine.cnn_model is None)
            )
            if need_load:
                load_models_and_data(request.model_type, dataset, is_startup=False)

            if request.mode in ('rf', 'hybrid') and engine.rf_model is None:
                raise ValueError('Requested Random Forest weights are unavailable.')
            if request.mode in ('cnn', 'hybrid') and engine.cnn_model is None:
                raise ValueError('Requested CNN weights are unavailable.')
            
            engine.execution_mode = request.mode
            initialize_lime_explainer()
            engine.last_error = None
            update_core_model_label()
        except Exception as exc:
            for k, v in previous_state.items():
                setattr(engine, k, v)
            system_status['rf_online'] = previous_rf_online
            system_status['cnn_online'] = previous_cnn_online
            update_core_model_label()
            raise HTTPException(409, f'Switch not applied: {exc}') from exc
        finally:
            engine.switching = False
    return {'status': 'ok', 'current_model': engine.current_model, 'execution_mode': engine.execution_mode}


@app.post('/api/heartbeat')
def hardware_heartbeat(heartbeat: Optional[dict] = None):
    engine.last_hardware_ping = time.time()
    # The Pi sensor refreshes its monitored-MAC allowlist from this response,
    # so devices added/removed in the dashboard take effect without editing
    # the sensor file or restarting it.
    try:
        monitored = get_monitored_devices()
    except Exception:
        monitored = []
    return {'status': 'ok', 'sensor_id': (heartbeat or {}).get('sensor_id', 'rpi3b-edge-01'),
            'hardware_live': True, 'monitored_devices': monitored}


@app.post('/api/ingest-flow')
def ingest_live_flow(flow: dict):
    if not flow.get('src_ip') or not flow.get('dst_ip'):
        raise HTTPException(422, 'src_ip and dst_ip are required')
    with engine_lock:
        engine.last_hardware_ping = time.time()
        engine.last_flow_received = time.time()
        system_status['processed_flows'] += 1
        prediction = confidence = p_rf = p_cnn = None
        failure = None
        frame = prepare_feature_dataframe(flow)
        try:
            prediction, confidence, p_rf, p_cnn = run_inference(frame)
            engine.last_error = None
        except Exception as exc:
            failure = str(exc)
            engine.last_error = failure
            system_status['inference_errors'] += 1
        is_alert = failure is None and alert_allowed(
            prediction, confidence, 
            dst_ip=str(flow.get('dst_ip', '')), 
            sni=flow.get('sni'),
            mac=flow.get('device_mac'),
            dst_port=flow.get('dst_port')
        )
        try:
            flow_id = insert_network_flow(
                src_ip=str(flow['src_ip']), dst_ip=str(flow['dst_ip']), proto=str(flow.get('proto', 'unknown')),
                duration=float(flow.get('duration', 0)), src_bytes=int(flow.get('src_bytes', 0)),
                dst_bytes=int(flow.get('dst_bytes', 0)), src_pkts=int(flow.get('src_pkts', 0)),
                dst_pkts=int(flow.get('dst_pkts', 0)), is_anomaly=int(is_alert),
                model_used=engine.current_model, execution_mode=engine.execution_mode, confidence=confidence,
                sensor_id=str(flow.get('sensor_id', 'rpi3b-edge-01')), device_name=flow.get('device_name'),
                device_mac=flow.get('device_mac'), src_port=flow.get('src_port'), dst_port=flow.get('dst_port'),
                prediction=prediction, p_rf=p_rf, p_cnn=p_cnn, data_source='live_hardware', inference_error=failure,
                sni=flow.get('sni'))
            if is_alert:
                record_threat_alert(flow, frame, confidence, 'live_hardware', flow_id)
        except Exception as exc:
            system_status['ingest_error'] = f'Flow or alert storage failed: {exc}'
            raise HTTPException(500, 'Flow or alert could not be saved; delivery is unconfirmed.') from exc
        system_status['ingest_error'] = None
        if failure:
            raise HTTPException(503, f'Flow saved without a prediction: {failure}')
        return dict(status='success', flow_id=flow_id, prediction=prediction, confidence=confidence,
                    p_rf=p_rf, p_cnn=p_cnn, mode=engine.execution_mode, model=engine.current_model)



def process_simulation():
    # Background simulation processing is disabled for live hardware capture mode.
    pass


async def simulate_live_traffic():
    # Background simulation worker is disabled for live hardware capture mode.
    pass
