import os
import sys
from pathlib import Path
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

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
    load_settings, save_settings, utc_now
)

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline, build_feature_row
from sentrix_ml.inference import run_single_inference
from sentrix_ml.packaging import validate_package, ModelManifest, PackageValidationError

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

engine = ActiveEngine()
engine_lock = RLock()
settings = {"active_alerting": True, "alert_threshold": 0.87}

# Explainability artifacts container
explainability = {
    "shap_values": None,
    "X_sample": None,
    "ripper_rules": None,
    "lime_explainer": None,
    "lime_feature_names": None,
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
    """Initialize a reusable LIME explainer from preloaded explainability samples."""
    try:
        lime_tabular = importlib.import_module("lime.lime_tabular")
    except Exception as e:
        print(f"LIME import unavailable: {e}")
        explainability["lime_explainer"] = None
        explainability["lime_feature_names"] = None
        return

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
        explainability["lime_explainer"] = lime_tabular.LimeTabularExplainer(
            training_data=X_numeric.to_numpy(dtype=float),
            feature_names=feature_names,
            class_names=["Benign", "Attack"],
            mode="classification",
            discretize_continuous=True,
        )
        print(f"LIME explainer initialized with {len(feature_names)} features")
    except Exception as e:
        explainability["lime_explainer"] = None
        explainability["lime_feature_names"] = None
        print(f"Failed to initialize LIME explainer: {e}")


def compute_lime_explanation_for_packet(inference_df: pd.DataFrame):
    """Compute top LIME contributors for one inference packet."""
    explainer = explainability.get("lime_explainer")
    feature_names = explainability.get("lime_feature_names")

    if explainer is None or not feature_names or engine.rf_model is None:
        return {"values": [], "target_class": None}

    try:
        row_df = inference_df.reindex(columns=feature_names, fill_value=0.0)
        row_df = row_df.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        row_arr = row_df.to_numpy(dtype=float)[0]

        def predict_fn(samples_np):
            samples_df = pd.DataFrame(samples_np, columns=feature_names).fillna(0.0)
            model_input = samples_df
            if hasattr(engine, "scaler") and engine.scaler is not None:
                model_input = engine.scaler.transform(samples_df)
            if hasattr(engine.rf_model, "predict_proba"):
                probabilities = engine.rf_model.predict_proba(model_input)
                classes = list(getattr(engine.rf_model, 'classes_', [0, 1]))
                if 0 not in classes or 1 not in classes:
                    raise ValueError('LIME requires benign class 0 and attack class 1.')
                return probabilities[:, [classes.index(0), classes.index(1)]]

            preds = engine.rf_model.predict(model_input)
            preds = np.array(preds, dtype=float).reshape(-1, 1)
            return np.hstack([1 - preds, preds])

        explanation = explainer.explain_instance(
            data_row=row_arr,
            predict_fn=predict_fn,
            num_features=3,
            top_labels=1,
        )

        labels = explanation.available_labels()
        target_label = 1 if 1 in labels else labels[0]
        lime_pairs = explanation.as_list(label=target_label)
        values = [
            {
                "f": str(feature_expr),
                "v": round(float(weight), 4),
            }
            for feature_expr, weight in lime_pairs
        ]
        return {"values": values, "target_class": int(target_label)}
    except Exception as e:
        print(f"Failed to compute LIME explanation: {e}")
        return {"values": [], "target_class": None}


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


def load_models_and_data(target="omni", dataset="omni"):
    print(f"Loading target '{target}' models and dataset '{dataset}'...")
    
    # Clear previous engine state before loading
    engine.rf_model = None
    engine.cnn_model = None
    engine.pipeline = None
    engine.scaler = None
    engine.manifest = None
    engine.package_dir = None
    engine.df = None
    engine.malicious_pool = None

    # 1. First check if a validated candidate package exists in models/candidates/{target}
    candidates_dir = os.path.join(os.path.dirname(__file__), "..", "models", "candidates", target)
    manifest_path = os.path.join(candidates_dir, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            print(f"Found candidate package for '{target}' in {candidates_dir}. Validating manifest...")
            manifest = validate_package(candidates_dir)
            engine.manifest = manifest
            engine.package_dir = candidates_dir

            rf_path = os.path.join(candidates_dir, manifest.rf_file)
            engine.rf_model = joblib.load(rf_path)
            system_status["rf_online"] = True

            cnn_path = os.path.join(candidates_dir, manifest.cnn_file)
            from tensorflow.keras.models import load_model
            engine.cnn_model = load_model(cnn_path, compile=False)
            system_status["cnn_online"] = True

            pipe_path = os.path.join(candidates_dir, manifest.preprocessor_file)
            engine.pipeline = PreprocessingPipeline.load(pipe_path)
            engine.scaler = engine.pipeline.scaler

            print(f"Candidate package '{target}' successfully validated and activated!")
            engine.current_dataset = dataset
            engine.current_model = target
            engine.last_error = None
            update_core_model_label()
            return
        except Exception as e:
            print(f"Candidate package validation/load failed: {e}")
            engine.last_error = f"Package validation error: {e}"

    # 2. Fallback to direct model files in models/ and scaler in data/processed/
    if target == "omni":
        rf_name = "rf_model_omni.joblib"
        cnn_name = "cnn_model_omni.h5"
    elif target == "ton_iot":
        rf_name = "rf_model_ton_iot.joblib"
        cnn_name = "cnn_model_ton_iot.h5"
    elif target == "bot_iot":
        rf_name = "rf_model_bot_iot_finetuned.joblib"
        cnn_name = "cnn_model_bot_iot_finetuned.h5"
    elif target == "cic_ids2017":
        rf_name = "rf_model_cic_ids2017_finetuned.joblib"
        cnn_name = "cnn_model_cic_ids2017_finetuned.h5"
    else:
        rf_name = f"rf_model_{target}.joblib"
        cnn_name = f"cnn_model_{target}.h5"

    model_path = os.path.join(os.path.dirname(__file__), "..", "models", rf_name)
    if os.path.exists(model_path):
        try:
            engine.rf_model = joblib.load(model_path)
            system_status["rf_online"] = True
            print(f"Loaded RF: {rf_name}")
        except Exception as e:
            print(f"Error loading RF: {e}")
            engine.rf_model = None

    scaler_path = os.path.join(os.path.dirname(__file__), "..", "data", "processed", f"{dataset}_scaler.pkl")
    if os.path.exists(scaler_path):
        try:
            loaded_scaler = joblib.load(scaler_path)
            engine.pipeline = PreprocessingPipeline(scaler=loaded_scaler, is_fitted=True)
            engine.scaler = loaded_scaler
            print(f"Loaded scaler: {dataset}_scaler.pkl")
        except Exception as e:
            print(f"Error loading scaler: {e}")
            engine.pipeline = None
            engine.scaler = None
    else:
        engine.pipeline = None
        engine.scaler = None

    cnn_path = os.path.join(os.path.dirname(__file__), "..", "models", cnn_name)
    if os.path.exists(cnn_path):
        try:
            from tensorflow.keras.models import load_model
            engine.cnn_model = load_model(cnn_path, compile=False)
            system_status["cnn_online"] = True
            print(f"Loaded CNN: {cnn_name}")
        except Exception as e:
            print(f"Error loading CNN: {e}")
            engine.cnn_model = None

    engine.current_dataset = dataset
    engine.current_model = target
    update_core_model_label()


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
    meta = {'shap_method': 'unavailable', 'shap_model': 'unknown', 'shap_target_class': None}
    
    # Check if stored SHAP belongs to active domain.
    # Existing stored artifacts (shap_values_attack.npy, X_sample.pkl) originate from ToN-IoT.
    # If active model is NOT ton_iot, reject reference SHAP lookup to prevent provenance mismatch!
    if engine.current_model != "ton_iot":
        meta["reason"] = f"Stored SHAP artifacts are from ToN-IoT; active model is '{engine.current_model}'."
    else:
        try:
            sample = explainability.get('X_sample')
            values = explainability.get('shap_values')
            if sample is not None and values is not None:
                common = [c for c in sample.columns if c in inference_df.columns]
                if common:
                    matrix = sample[common].to_numpy(dtype=float)
                    target = inference_df[common].to_numpy(dtype=float)[0]
                    idx = int(np.argmin(np.sum((matrix - target) ** 2, axis=1)))
                    arr = np.asarray(values)
                    n, features = len(sample), len(sample.columns)
                    vector = None
                    if arr.ndim == 2 and arr.shape == (n, features):
                        vector = arr[idx]
                    elif arr.ndim == 3 and arr.shape == (2, n, features):
                        vector = arr[1, idx]
                    elif arr.ndim == 3 and arr.shape == (n, features, 2):
                        vector = arr[idx, :, 1]
                    if vector is not None and np.all(np.isfinite(vector)):
                        top = np.argsort(np.abs(vector))[-5:][::-1]
                        meta.update(shap_method='reference_sample_shap', reference_index=idx,
                                    shap_target_class=1, reference_file='shap_values_attack.npy')
                        return [{'f': str(sample.columns[i]), 'v': float(vector[i])} for i in top], meta
        except Exception as exc:
            print(f'Reference explanation unavailable: {exc}')

    # Global RF feature importance fallback
    if engine.rf_model is not None and hasattr(engine.rf_model, 'feature_importances_'):
        values = np.asarray(engine.rf_model.feature_importances_)
        names = getattr(engine.rf_model, 'feature_names_in_', EXPECTED_FEATURES)
        if len(values) == len(names) and np.all(np.isfinite(values)):
            top = np.argsort(values)[-5:][::-1]
            meta.update(shap_method='global_rf_importance', shap_model='random_forest')
            return [{'f': str(names[i]), 'v': float(values[i])} for i in top], meta

    return [], meta


def record_threat_alert(packet_data, inference_df, confidence, source, flow_id=None):
    features, metadata = reference_explanation(inference_df)
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


def alert_allowed(prediction, confidence):
    return settings['active_alerting'] and prediction == 1 and confidence > settings['alert_threshold']


@app.on_event('startup')
async def startup_event():
    init_db()
    stored = load_settings(settings)
    settings.update(SettingsRequest(**stored).model_dump())
    load_models_and_data('omni', 'omni')
    directory = os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', 'explainability')
    for filename, key in [('shap_values_attack.npy', 'shap_values'), ('X_sample.pkl', 'X_sample'),
                          ('ripper_rules.txt', 'ripper_rules')]:
        path = os.path.join(directory, filename)
        if not os.path.exists(path):
            continue
        try:
            if filename.endswith('.npy'):
                explainability[key] = np.load(path, allow_pickle=True)
            elif filename.endswith('.pkl'):
                explainability[key] = pd.read_pickle(path)
            else:
                with open(path, encoding='utf-8') as file:
                    explainability[key] = file.read()
        except Exception as exc:
            print(f'Explanation artifact unavailable ({filename}): {exc}')
    initialize_lime_explainer()


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


@app.get('/api/database/stats')
def get_db_stats():
    return get_database_stats()


@app.get('/api/model-metrics')
def get_model_metrics():
    # 1. If active engine has a validated candidate package with evaluation file:
    if engine.manifest and engine.manifest.evaluation_file and engine.package_dir:
        eval_path = os.path.join(engine.package_dir, engine.manifest.evaluation_file)
        if os.path.exists(eval_path):
            try:
                with open(eval_path, encoding='utf-8') as f:
                    data = json.load(f)
                # Verify run_type is "full"
                if data.get("run_type") == "full":
                    metrics = {}
                    for key in ('accuracy', 'precision', 'recall', 'f1', 'roc_auc'):
                        val = data.get(key)
                        if isinstance(val, (int, float)) and not isinstance(val, bool) and np.isfinite(val) and 0 <= val <= 1:
                            metrics[key] = val
                    return {
                        'available': bool(metrics),
                        'model': engine.current_model,
                        'mode': engine.execution_mode,
                        'dataset': data.get('dataset', engine.current_dataset),
                        'evaluation_split': data.get('evaluation_split', 'independent_test_holdout'),
                        'source': f"sentrix_ml package ({engine.manifest.package_version})",
                        'metrics': metrics,
                    }
                else:
                    return {'available': False, 'reason': 'Smoke evaluation metrics not published to API'}
            except Exception as e:
                print(f"Error reading package evaluation metrics: {e}")

    # 2. Fallback to optional legacy model_metrics.json (only if valid full evaluation)
    path = os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', 'model_metrics.json')
    try:
        with open(path, encoding='utf-8') as file:
            entry = json.load(file).get(engine.current_model, {}).get(engine.execution_mode)
        if not isinstance(entry, dict) or not all(entry.get(k) for k in ('dataset', 'evaluation_split', 'source')):
            return {'available': False}
        if entry.get("run_type") == "smoke":
            return {'available': False, 'reason': 'Smoke run metrics not published to API'}
        metrics = {}
        for key in ('accuracy', 'precision', 'recall', 'f1', 'roc_auc'):
            value = entry.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and np.isfinite(value) and 0 <= value <= 1:
                metrics[key] = value
        return {'available': bool(metrics), 'model': engine.current_model, 'mode': engine.execution_mode,
                'dataset': entry['dataset'], 'evaluation_split': entry['evaluation_split'],
                'source': entry['source'], 'metrics': metrics}
    except (OSError, ValueError, TypeError, AttributeError):
        return {'available': False}


@app.get('/api/explainability/ripper')
def get_ripper_rules():
    return {'rules': explainability.get('ripper_rules') or '', 'scope': 'stored_reference_rules',
            'evaluated_on_live_flow': False}


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
        previous = vars(engine).copy()
        engine.switching = True
        try:
            dataset = request.dataset or request.model_type
            if dataset != request.model_type:
                raise ValueError('Model and preprocessing dataset must match.')
            engine.execution_mode = request.mode
            if (engine.current_model != request.model_type or engine.current_dataset != dataset
                    or (request.mode in ('rf', 'hybrid') and engine.rf_model is None)
                    or (request.mode in ('cnn', 'hybrid') and engine.cnn_model is None)):
                load_models_and_data(request.model_type, dataset)
            if request.mode in ('rf', 'hybrid') and engine.rf_model is None:
                raise ValueError('Requested Random Forest weights are unavailable.')
            if request.mode in ('cnn', 'hybrid') and engine.cnn_model is None:
                raise ValueError('Requested CNN weights are unavailable.')
            initialize_lime_explainer()
            engine.last_error = None
            update_core_model_label()
        except Exception as exc:
            vars(engine).update(previous)
            update_core_model_label()
            raise HTTPException(409, f'Switch not applied: {exc}') from exc
        finally:
            engine.switching = False
    return {'status': 'ok', 'current_model': engine.current_model, 'execution_mode': engine.execution_mode}


@app.post('/api/heartbeat')
def hardware_heartbeat(heartbeat: Optional[dict] = None):
    engine.last_hardware_ping = time.time()
    return {'status': 'ok', 'sensor_id': (heartbeat or {}).get('sensor_id', 'rpi3b-edge-01'),
            'hardware_live': True}


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
        is_alert = failure is None and alert_allowed(prediction, confidence)
        try:
            flow_id = insert_network_flow(
                src_ip=str(flow['src_ip']), dst_ip=str(flow['dst_ip']), proto=str(flow.get('proto', 'unknown')),
                duration=float(flow.get('duration', 0)), src_bytes=int(flow.get('src_bytes', 0)),
                dst_bytes=int(flow.get('dst_bytes', 0)), src_pkts=int(flow.get('src_pkts', 0)),
                dst_pkts=int(flow.get('dst_pkts', 0)), is_anomaly=int(is_alert),
                model_used=engine.current_model, execution_mode=engine.execution_mode, confidence=confidence,
                sensor_id=str(flow.get('sensor_id', 'rpi3b-edge-01')), device_name=flow.get('device_name'),
                device_mac=flow.get('device_mac'), src_port=flow.get('src_port'), dst_port=flow.get('dst_port'),
                prediction=prediction, p_rf=p_rf, p_cnn=p_cnn, data_source='live_hardware', inference_error=failure)
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


@app.post('/api/inject-attack')
def deploy_attack(request: AttackRequest):
    raise HTTPException(403, 'Attack injection is disabled. SENTRi-X operates exclusively in live hardware capture mode.')


def process_simulation():
    # Background simulation processing is disabled for live hardware capture mode.
    pass


async def simulate_live_traffic():
    # Background simulation worker is disabled for live hardware capture mode.
    pass
