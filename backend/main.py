import os
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import pandas as pd
import random
import time
import asyncio
import joblib
import psutil
import numpy as np
import json
import pickle
import re
import importlib
from database import (
    init_db,
    insert_network_flow,
    insert_alert,
    get_all_alerts,
    clear_all_alerts,
    get_database_stats
)

app = FastAPI(title="SENTRi-X Backend API", description="Hybrid & Explainable NIDS Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Standard Expected Feature Schema (30 Features)
EXPECTED_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts',
    'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_qclass', 'dns_qtype',
    'dns_rcode', 'http_request_body_len', 'http_response_body_len', 
    'http_status_code', 'proto_tcp', 'proto_udp', 'conn_state_REJ', 
    'conn_state_RSTO', 'conn_state_RSTOS0', 'conn_state_RSTR',      
    'conn_state_RSTRH', 'conn_state_S0', 'conn_state_S1', 'conn_state_S2',
    'conn_state_S3', 'conn_state_SF', 'conn_state_SH', 'conn_state_SHR'
]

# Active Model Refs Object
class ActiveEngine:
    def __init__(self):
        self.rf_model = None
        self.cnn_model = None
        self.scaler = None
        self.df = None
        self.malicious_pool = None
        self.attack_queue = []
        self.current_dataset = "omni"
        self.current_model = "omni"
        self.execution_mode = "hybrid"  # "hybrid" | "rf" | "cnn"
        self.data_source = "simulation"  # "simulation" | "live_hardware"
        self.last_hardware_ping = 0.0
        self.row_idx = 0

engine = ActiveEngine()
current_threats = []

# Explainability artifacts container
explainability = {
    "shap_values": None,
    "X_sample": None,
    "ripper_rules": None,
    "lime_explainer": None,
    "lime_feature_names": None,
}

# Network traffic tracking for real metrics
traffic_metrics = {
    "bytes_processed": 0,
    "last_traffic_sample": 0,
    "traffic_history": []
}

system_status = {
    "node_status": "Active",
    "core_model": "Hybrid Ensemble (RF+CNN) - OMNI (GLOBAL)",
    "current_dataset": "omni",
    "current_model": "omni",
    "execution_mode": "hybrid",
    "data_source": "simulation",
    "is_hardware_live": False,
    "processed_packets": 0,
    "threats_detected": 0,
    "cpu_usage": 45,
    "memory_usage": 60,
    "rf_online": False,
    "cnn_online": False,
    "chart_data": [40, 60, 35, 70, 55, 80, 50, 65, 45, 75],
    "latest_shap": [
        {"f": "src_bytes", "v": 0.62},
        {"f": "dst_pkts", "v": 0.31},
        {"f": "duration", "v": 0.14},
    ],
    "latest_lime": [
        {"f": "src_bytes", "v": 0.0},
        {"f": "dst_pkts", "v": 0.0},
        {"f": "duration", "v": 0.0},
    ],
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


def _extract_lime_feature_key(feature_expr: str, known_feature_names: list[str]) -> str:
    for feature_name in sorted(known_feature_names, key=len, reverse=True):
        if re.search(rf"\b{re.escape(feature_name)}\b", feature_expr):
            return feature_name
    return feature_expr


def compute_lime_explanation_for_packet(inference_df: pd.DataFrame):
    """Compute top LIME contributors for one inference packet."""
    explainer = explainability.get("lime_explainer")
    feature_names = explainability.get("lime_feature_names")

    if explainer is None or not feature_names:
        return []

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
                return engine.rf_model.predict_proba(model_input)

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
        return [
            {
                "f": _extract_lime_feature_key(str(feature_expr), feature_names),
                "v": round(float(weight), 4),
            }
            for feature_expr, weight in lime_pairs
        ]
    except Exception as e:
        print(f"Failed to compute LIME explanation: {e}")
        return []


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
    
    # 1. Resolve filenames
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

    # Load RF
    model_path = os.path.join(os.path.dirname(__file__), "..", "models", rf_name)
    if os.path.exists(model_path):
        try:
            engine.rf_model = joblib.load(model_path)
            system_status["rf_online"] = True
            print(f"Loaded RF: {rf_name}")
        except Exception as e:
            print(f"Error loading RF: {e}")
            engine.rf_model = None

    # Load Scaler
    scaler_path = os.path.join(os.path.dirname(__file__), "..", "data", "processed", f"{dataset}_scaler.pkl")
    if os.path.exists(scaler_path):
        try:
            engine.scaler = joblib.load(scaler_path)
        except Exception:
            engine.scaler = None
    else:
        engine.scaler = None

    # Load CNN
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

    # Load Simulation Dataset
    try:
        if dataset == "omni":
            ton_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "ton_iot", "Network_dataset_1.csv")
            bot_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "bot_iot", "bot_iot_mapped.csv")
            cic_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "cic_ids2017", "cic_ids2017_mapped.csv")
            if not os.path.exists(cic_path):
                cic_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "cic_ids2017", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

            pools_normal = []
            pools_attack = []

            if os.path.exists(ton_path):
                t_df = pd.read_csv(ton_path, nrows=10000, low_memory=False)
                t_col = 'Label' if 'Label' in t_df.columns else 'label'
                if t_col in t_df.columns:
                    t_norm = t_df[t_df[t_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    t_attk = t_df[~t_df[t_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    if len(t_norm) > 0: pools_normal.append(t_norm.sample(n=min(1500, len(t_norm))))
                    if len(t_attk) > 0: pools_attack.append(t_attk.sample(n=min(500, len(t_attk))))

            if os.path.exists(bot_path):
                b_df = pd.read_csv(bot_path, nrows=10000, low_memory=False)
                b_col = 'Label' if 'Label' in b_df.columns else 'label'
                if b_col in b_df.columns:
                    b_norm = b_df[b_df[b_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    b_attk = b_df[~b_df[b_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    if len(b_norm) > 0: pools_normal.append(b_norm.sample(n=min(1500, len(b_norm))))
                    if len(b_attk) > 0: pools_attack.append(b_attk.sample(n=min(500, len(b_attk))))

            if os.path.exists(cic_path):
                c_df = pd.read_csv(cic_path, nrows=10000, low_memory=False)
                c_col = 'Label' if 'Label' in c_df.columns else 'label'
                if c_col in c_df.columns:
                    c_norm = c_df[c_df[c_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    c_attk = c_df[~c_df[c_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    if len(c_norm) > 0: pools_normal.append(c_norm.sample(n=min(1500, len(c_norm))))
                    if len(c_attk) > 0: pools_attack.append(c_attk.sample(n=min(500, len(c_attk))))

            if pools_normal:
                engine.df = pd.concat(pools_normal, ignore_index=True).sample(frac=1).reset_index(drop=True)
            if pools_attack:
                engine.malicious_pool = pd.concat(pools_attack, ignore_index=True).sample(frac=1).reset_index(drop=True)

        else:
            if dataset == "ton_iot":
                csv_file = "Network_dataset_1.csv"
                sub_dir = "ton_iot"
            elif dataset == "bot_iot":
                csv_file = "bot_iot_mapped.csv"
                sub_dir = "bot_iot"
            else:
                csv_file = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
                sub_dir = "cic_ids2017"

            data_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", sub_dir, csv_file)
            if os.path.exists(data_path):
                full_df = pd.read_csv(data_path, nrows=10000, low_memory=False)
                label_col = 'Label' if 'Label' in full_df.columns else 'label'
                if label_col in full_df.columns:
                    normal_rows = full_df[full_df[label_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                    attack_rows = full_df[~full_df[label_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
                else:
                    normal_rows = full_df
                    attack_rows = full_df.head(100)

                if len(normal_rows) > 0:
                    engine.df = normal_rows.sample(n=min(5000, len(normal_rows))).reset_index(drop=True)
                if len(attack_rows) > 0:
                    engine.malicious_pool = attack_rows.sample(n=min(1000, len(attack_rows))).reset_index(drop=True)
                del full_df

        engine.row_idx = 0
        engine.attack_queue = []
    except Exception as e:
        print(f"Error loading dataset pool: {e}")

    engine.current_dataset = dataset
    engine.current_model = target
    update_core_model_label()


def prepare_feature_dataframe(packet_data):
    """Aligns dictionary or Series packet data into the 30-feature vector."""
    inference_df = pd.DataFrame(0.0, index=[0], columns=EXPECTED_FEATURES)

    numeric_cols = [
        'duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts',
        'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_qclass', 'dns_qtype',
        'dns_rcode', 'http_request_body_len', 'http_response_body_len', 'http_status_code'
    ]

    is_dict = isinstance(packet_data, dict)
    
    for col in numeric_cols:
        val = packet_data.get(col, 0) if is_dict else (packet_data[col] if col in packet_data else 0)
        if val == '-' or val is None:
            val = 0
        inference_df.at[0, col] = pd.to_numeric(val, errors='coerce')

    inference_df = inference_df.fillna(0.0)

    # Protocols
    if is_dict:
        if packet_data.get("proto_tcp") == 1:
            inference_df.at[0, "proto_tcp"] = 1.0
        if packet_data.get("proto_udp") == 1:
            inference_df.at[0, "proto_udp"] = 1.0
        for col in EXPECTED_FEATURES:
            if col.startswith("conn_state_") and packet_data.get(col) == 1:
                inference_df.at[0, col] = 1.0
    else:
        if 'proto' in packet_data:
            proto_val = str(packet_data['proto']).lower()
            if f'proto_{proto_val}' in EXPECTED_FEATURES:
                inference_df.at[0, f'proto_{proto_val}'] = 1.0
        if 'conn_state' in packet_data:
            conn_val = str(packet_data['conn_state']).upper()
            if f'conn_state_{conn_val}' in EXPECTED_FEATURES:
                inference_df.at[0, f'conn_state_{conn_val}'] = 1.0

    return inference_df


def run_inference(inference_df: pd.DataFrame):
    """Executes inference respecting engine.execution_mode ('hybrid', 'rf', 'cnn')."""
    scaled_input = inference_df
    if hasattr(engine, "scaler") and engine.scaler is not None:
        try:
            scaled_input = engine.scaler.transform(inference_df)
        except Exception:
            scaled_input = inference_df

    p_rf = 0.0
    p_cnn = 0.0

    # 1. Random Forest Inference
    if engine.rf_model is not None and engine.execution_mode in ["rf", "hybrid"]:
        try:
            if hasattr(engine.rf_model, "predict_proba"):
                probs = engine.rf_model.predict_proba(scaled_input)[0]
                p_rf = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                p_rf = float(engine.rf_model.predict(scaled_input)[0])
        except Exception as e:
            print(f"RF inference error: {e}")
            p_rf = 0.0

    # 2. 1D CNN Inference
    if engine.cnn_model is not None and engine.execution_mode in ["cnn", "hybrid"]:
        try:
            tensor_arr = np.array(scaled_input, dtype=float).reshape(1, inference_df.shape[1], 1)
            raw_cnn_out = engine.cnn_model.predict(tensor_arr, verbose=0)
            if hasattr(raw_cnn_out, "ndim") and raw_cnn_out.shape[-1] > 1:
                p_cnn = float(raw_cnn_out[0][1])
            else:
                p_cnn = float(raw_cnn_out[0][0])
        except Exception as e:
            print(f"CNN inference error: {e}")
            p_cnn = p_rf  # Fallback

    # 3. Soft-Voting Fusion / Mode Branching
    if engine.execution_mode == "rf":
        final_p = p_rf
    elif engine.execution_mode == "cnn":
        final_p = p_cnn
    else:  # Hybrid Ensemble
        if engine.rf_model is not None and engine.cnn_model is not None:
            final_p = (p_rf + p_cnn) / 2.0
        elif engine.rf_model is not None:
            final_p = p_rf
        else:
            final_p = p_cnn

    prediction = 1 if final_p >= 0.5 else 0
    confidence = round(float(final_p if prediction == 1 else (1.0 - final_p)), 4)
    return prediction, confidence, p_rf, p_cnn


def record_threat_alert(packet_data, inference_df, confidence):
    """Generates XAI diagnostics and appends threat alert to active logs."""
    system_status["threats_detected"] += 1

    threat_shap = None
    threat_lime = []

    try:
        shap_loaded = explainability.get("shap_values")
        X_sample_loaded = explainability.get("X_sample")
        if shap_loaded is not None and X_sample_loaded is not None:
            common_cols = [c for c in X_sample_loaded.columns if c in inference_df.columns]
            if len(common_cols) > 0:
                sample_matrix = X_sample_loaded[common_cols].to_numpy(dtype=float)
                target_vec = inference_df[common_cols].to_numpy(dtype=float)[0]
                dists = np.sum((sample_matrix - target_vec) ** 2, axis=1)
                nearest_idx = int(np.argmin(dists))
                shap_arr = np.array(shap_loaded)
                if shap_arr.ndim == 3:
                    shap_vec = shap_arr[-1, nearest_idx, :]
                elif shap_arr.ndim == 2:
                    shap_vec = shap_arr[nearest_idx, :]
                else:
                    shap_vec = shap_arr[nearest_idx]

                feat_names = list(X_sample_loaded.columns)
                abs_idx = np.argsort(np.abs(shap_vec))[-3:][::-1]
                threat_shap = [
                    {"f": str(feat_names[i]) if i < len(feat_names) else f"feature_{i}", "v": round(float(shap_vec[i]), 4)}
                    for i in abs_idx
                ]
                system_status["latest_shap"] = threat_shap
    except Exception as e:
        print(f"SHAP extraction error: {e}")

    if not threat_shap and hasattr(engine.rf_model, "feature_importances_"):
        try:
            importances = engine.rf_model.feature_importances_
            feature_names = getattr(engine.rf_model, "feature_names_in_", EXPECTED_FEATURES)
            top_indices = np.argsort(importances)[-3:][::-1]
            threat_shap = [
                {"f": str(feature_names[idx]) if idx < len(feature_names) else f"feature_{idx}", "v": round(float(importances[idx]), 2)}
                for idx in top_indices
            ]
            system_status["latest_shap"] = threat_shap
        except Exception:
            pass

    threat_lime = compute_lime_explanation_for_packet(inference_df)
    if threat_lime:
        system_status["latest_lime"] = threat_lime

    # Extract IPs
    is_dict = isinstance(packet_data, dict)
    src_ip = packet_data.get("src_ip") if is_dict else (packet_data.get("src") if hasattr(packet_data, "get") else None)
    dst_ip = packet_data.get("dst_ip") if is_dict else (packet_data.get("dst") if hasattr(packet_data, "get") else None)

    if not src_ip:
        src_ip = f"192.168.1.{random.randint(2, 254)}"
    if not dst_ip:
        dst_ip = f"10.0.0.{random.randint(1, 100)}"

    label_val = packet_data.get("type") or packet_data.get("Label") or packet_data.get("label") if is_dict else (packet_data.get("type") if hasattr(packet_data, "get") else None)
    actual_type = str(label_val) if label_val and str(label_val).lower() not in ['normal', 'benign', '0', 'nan'] else "Malicious Flow Anomaly"

    threat_level = classify_threat_level(confidence)
    mode_tag = engine.execution_mode.upper()
    domain_tag = engine.current_model.upper()

    new_threat = {
        "id": str(int(time.time() * 1000)),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": str(src_ip),
        "target_ip": str(dst_ip),
        "dest_ip": str(dst_ip),
        "attack_type": actual_type,
        "confidence": confidence,
        "threat_level": threat_level,
        "status": f"{threat_level.upper()} ALERT ({mode_tag}-{domain_tag})",
        "model_type": engine.current_model,
        "execution_mode": engine.execution_mode,
        "shap_values": threat_shap if threat_shap else [],
        "lime_values": threat_lime if threat_lime else []
    }

    try:
        insert_alert(new_threat)
    except Exception as e:
        print(f"Error persisting alert to database: {e}")

    current_threats.insert(0, new_threat)
    if len(current_threats) > 100:
        current_threats.pop()


@app.on_event("startup")
async def startup_event():
    current_threats.clear()
    engine.attack_queue.clear()
    engine.row_idx = 0
    system_status["processed_packets"] = 0
    system_status["threats_detected"] = 0
    system_status["chart_data"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    
    try:
        init_db()
        db_alerts = get_all_alerts(50)
        current_threats.extend(db_alerts)
        system_status["threats_detected"] = len(db_alerts)
        print(f"SQLite DB initialized. Loaded {len(db_alerts)} historical alerts.")
    except Exception as e:
        print(f"Error initializing SQLite DB: {e}")

    load_models_and_data("omni", "omni")
    
    try:
        expl_dir = os.path.join(os.path.dirname(__file__), "..", "data", "processed", "explainability")
        shap_path = os.path.join(expl_dir, "shap_values_attack.npy")
        sample_path = os.path.join(expl_dir, "X_sample.pkl")
        ripper_path = os.path.join(expl_dir, "ripper_rules.txt")

        if os.path.exists(shap_path):
            explainability["shap_values"] = np.load(shap_path, allow_pickle=True)
        if os.path.exists(sample_path):
            try:
                explainability["X_sample"] = pd.read_pickle(sample_path)
            except Exception:
                with open(sample_path, "rb") as f:
                    explainability["X_sample"] = pickle.load(f)
        if os.path.exists(ripper_path):
            with open(ripper_path, "r", encoding="utf-8") as f:
                explainability["ripper_rules"] = f.read()
        initialize_lime_explainer()
    except Exception as e:
        print("Failed to load explainability artifacts:", e)

    asyncio.create_task(simulate_live_traffic())


@app.get("/")
def read_root():
    return {
        "message": "SENTRi-X Hybrid NIDS Engine Active",
        "current_model": engine.current_model,
        "execution_mode": engine.execution_mode,
        "data_source": engine.data_source
    }


@app.get("/api/status")
def get_status():
    try:
        system_status["cpu_usage"] = max(0, min(100, psutil.cpu_percent(interval=0.1)))
        system_status["memory_usage"] = psutil.virtual_memory().percent
    except Exception:
        system_status["cpu_usage"] = 45
        system_status["memory_usage"] = 55

    is_hw_live = (time.time() - engine.last_hardware_ping) < 5.0
    system_status["is_hardware_live"] = is_hw_live
    system_status["data_source"] = "live_hardware" if is_hw_live else "simulation"
    update_core_model_label()
    return system_status


@app.get("/api/threat-logs")
def get_threat_logs():
    try:
        db_logs = get_all_alerts(100)
        return {"logs": db_logs}
    except Exception:
        return {"logs": current_threats[:50]}


@app.get("/api/database/stats")
def get_db_stats():
    return get_database_stats()


@app.get("/api/explainability/sample/{idx}")
def get_explainability_sample(idx: int):
    shap_arr = explainability.get("shap_values")
    X_sample_df = explainability.get("X_sample")
    if shap_arr is None or X_sample_df is None or idx < 0 or idx >= len(X_sample_df):
        return {"error": "Explainability sample not available"}

    sample_row = X_sample_df.iloc[idx].to_dict()
    shap_vec = None
    try:
        shap_np = np.array(shap_arr)
        if shap_np.ndim == 3:
            shap_vec = shap_np[-1, idx, :].tolist()
        elif shap_np.ndim == 2:
            shap_vec = shap_np[idx, :].tolist()
        else:
            shap_vec = shap_np[idx].tolist()
    except Exception:
        shap_vec = None

    return {"index": idx, "sample": sample_row, "shap": shap_vec}


@app.get("/api/explainability/ripper")
def get_ripper_rules():
    rules = explainability.get("ripper_rules")
    return {"rules": rules} if rules else {"error": "RIPPER rules not available"}


@app.post("/api/clear")
def clear_dashboard_data():
    global current_threats
    current_threats.clear()
    engine.attack_queue.clear()
    system_status["processed_packets"] = 0
    system_status["threats_detected"] = 0
    system_status["chart_data"] = [0] * 10
    try:
        clear_all_alerts()
    except Exception as e:
        print(f"Error clearing database: {e}")
    return {"message": "Dashboard logs, SQLite database, and metrics reset."}


class SwitchRequest(BaseModel):
    model_type: Optional[str] = "omni"
    dataset: Optional[str] = "omni"
    mode: Optional[str] = "hybrid"  # "hybrid" | "rf" | "cnn"


class AttackRequest(BaseModel):
    type: str = "DDoS"
    intensity: int = 5


@app.post("/api/inject-attack")
def deploy_attack(req: AttackRequest):
    if engine.malicious_pool is None or len(engine.malicious_pool) == 0:
        return {"message": "Failed", "error": "No malicious pool loaded for current domain."}

    print(f"RED TEAM INJECTION: {req.intensity} {req.type} attack nodes queued!")
    packets_to_inject = engine.malicious_pool.sample(n=min(req.intensity, len(engine.malicious_pool)))

    for i in range(len(packets_to_inject)):
        packet = packets_to_inject.iloc[[i]].copy()
        if 'type' in packet.columns:
            packet['type'] = req.type
        elif 'Label' in packet.columns:
            packet['Label'] = req.type
        elif 'label' in packet.columns:
            packet['label'] = req.type
        engine.attack_queue.append(packet)

    system_status["node_status"] = f"ALERT: {req.type.upper()} INJECTION RECEIVED"
    return {"message": f"Injected {req.intensity} attack packets ({req.type}).", "queue_size": len(engine.attack_queue)}


@app.post("/api/switch")
def switch_engine(req: SwitchRequest):
    target_domain = (req.model_type or "omni").lower()
    target_dataset = (req.dataset or target_domain).lower()
    target_mode = (req.mode or "hybrid").lower()

    if target_mode not in ["hybrid", "rf", "cnn"]:
        target_mode = "hybrid"

    print(f"SWITCH REQUEST: Domain -> {target_domain}, Dataset -> {target_dataset}, Mode -> {target_mode}")

    engine.execution_mode = target_mode

    # If domain changed, reload weights
    if target_domain != engine.current_model or target_dataset != engine.current_dataset or engine.rf_model is None:
        load_models_and_data(target_domain, target_dataset)
        initialize_lime_explainer()
    else:
        update_core_model_label()

    return {
        "message": f"Switched to {engine.current_model} with {engine.execution_mode.upper()} mode.",
        "core_model": system_status["core_model"],
        "execution_mode": engine.execution_mode,
        "rf_online": system_status["rf_online"],
        "cnn_online": system_status["cnn_online"]
    }


@app.post("/api/ingest-flow")
def ingest_live_flow(flow: dict):
    """Receives real-time bidirectional flow features from Raspberry Pi 3B+ edge sensor."""
    engine.data_source = "live_hardware"
    engine.last_hardware_ping = time.time()
    system_status["node_status"] = "Live Monitoring (RPi 3B+ Edge Sensor)"
    system_status["processed_packets"] += 1

    flow_bytes = flow.get("src_bytes", 500) + flow.get("dst_bytes", 0)
    traffic_metrics["bytes_processed"] += flow_bytes

    inference_df = prepare_feature_dataframe(flow)
    prediction, confidence, p_rf, p_cnn = run_inference(inference_df)

    is_threat = (prediction == 1) and (confidence > 0.87)
    
    try:
        insert_network_flow(
            src_ip=str(flow.get("src_ip", "192.168.1.50")),
            dst_ip=str(flow.get("dst_ip", "10.0.0.1")),
            proto=str(flow.get("proto", "TCP")),
            duration=float(flow.get("duration", 0.0)),
            src_bytes=int(flow.get("src_bytes", 0)),
            dst_bytes=int(flow.get("dst_bytes", 0)),
            src_pkts=int(flow.get("src_pkts", 0)),
            dst_pkts=int(flow.get("dst_pkts", 0)),
            is_anomaly=1 if is_threat else 0,
            model_used=engine.current_model,
            confidence=float(confidence),
            sensor_id=str(flow.get("sensor_id", "rpi3b-edge-01"))
        )
    except Exception as e:
        print(f"Error persisting flow to database: {e}")

    if is_threat:
        record_threat_alert(flow, inference_df, confidence)

    return {
        "status": "success",
        "prediction": int(prediction),
        "confidence": float(confidence),
        "p_rf": float(p_rf),
        "p_cnn": float(p_cnn),
        "mode": engine.execution_mode,
        "model": engine.current_model
    }


async def simulate_live_traffic():
    """Background simulator loop: generates ambient traffic or processes Red Team attack queue."""
    print("Background traffic worker initialized...")

    while True:
        await asyncio.sleep(1.5)

        # If real Raspberry Pi hardware is actively streaming, pause simulator to avoid clutter
        if (time.time() - engine.last_hardware_ping) < 4.0:
            continue

        system_status["processed_packets"] += 1
        estimated_packet_size = random.randint(100, 2000)
        traffic_metrics["bytes_processed"] += estimated_packet_size

        baseline = 40 + (system_status["threats_detected"] % 10) * 3
        traffic_component = min(30, (traffic_metrics["bytes_processed"] % 5000) / 200)
        new_vol = int(max(0, min(100, baseline + traffic_component + random.randint(-5, 5))))
        system_status["chart_data"] = system_status["chart_data"][1:] + [new_vol]

        if engine.df is not None and len(engine.df) > 0 and (engine.rf_model is not None or engine.cnn_model is not None):
            from_attack_queue = len(engine.attack_queue) > 0
            if from_attack_queue:
                current_packet = engine.attack_queue.pop(0)
            else:
                if engine.row_idx >= len(engine.df):
                    engine.row_idx = 0
                current_packet = engine.df.iloc[[engine.row_idx]]
                engine.row_idx += 1

            packet_data = current_packet.iloc[0]
            inference_df = prepare_feature_dataframe(packet_data)
            prediction, confidence, p_rf, p_cnn = run_inference(inference_df)

            is_threat = from_attack_queue and (prediction == 1) and (confidence > 0.87)

            if is_threat:
                record_threat_alert(packet_data, inference_df, confidence)
            else:
                system_status["latest_shap"] = [
                    {"f": "src_bytes", "v": 0.03},
                    {"f": "dst_pkts", "v": 0.02},
                    {"f": "duration", "v": 0.01},
                ]
                system_status["latest_lime"] = [
                    {"f": "src_bytes", "v": 0.02},
                    {"f": "dst_pkts", "v": 0.01},
                    {"f": "duration", "v": -0.01},
                ]
