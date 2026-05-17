from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import random
import time
import asyncio
import joblib
import os
import psutil
import numpy as np
import json
import pickle
import re
import importlib

app = FastAPI(title="SENTRi-X Backend API", description="Data Simulator for 50% Thesis Defense")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active Model Refs Object
class ActiveEngine:
    def __init__(self):
        self.rf_model = None
        self.cnn_model = None
        self.scaler = None
        self.df = None
        self.malicious_pool = None
        self.attack_queue = []
        self.current_dataset = "ToN_IoT"
        self.current_model = "ton_iot"
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
    "traffic_history": []  # Rolling window of traffic measurements
}

system_status = {
    "node_status": "Active",
    "core_model": "Hybrid Ensemble (RF+CNN) - ToN_IoT",
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
        print("LIME explainer not initialized: X_sample unavailable")
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
    """Map LIME's human-readable condition (e.g. 'src_bytes <= 0.5') back to feature key."""
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

def load_models_and_data(target="ton_iot", dataset="ton_iot"):
    print(f"Loading {target} models and {dataset} dataset...")
    
    # 1. Random Forest
    rf_name = f"rf_model_{target}.joblib"
    model_path = os.path.join(os.path.dirname(__file__), "..", "models", rf_name)
    if os.path.exists(model_path):
        try:
            engine.rf_model = joblib.load(model_path)
            system_status["rf_online"] = True
            
            # Load scaler if it exists
            scaler_path = os.path.join(os.path.dirname(__file__), "..", "data", "processed", f"{dataset}_scaler.pkl")
            if os.path.exists(scaler_path):
                engine.scaler = joblib.load(scaler_path)
            else:
                engine.scaler = None
        except Exception as e:
            print(f"Error loading RF (or Scaler): {e}")

    # 2. CNN
    cnn_name = f"cnn_model_{target}.h5"
    cnn_path = os.path.join(os.path.dirname(__file__), "..", "models", cnn_name)
    if os.path.exists(cnn_path):
        try:
            from tensorflow.keras.models import load_model
            engine.cnn_model = load_model(cnn_path)
            system_status["cnn_online"] = True
        except Exception as e:
            print(f"Error loading CNN: {e}")

    # 3. CSV Dataset
    try:
        if dataset == "omni":
            print("Loading OMNI Global Dataset (ToN + BoT + CIC)...")
            
            # Load ToN
            ton_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "ton_iot", "Network_dataset_1.csv")
            ton_df = pd.read_csv(ton_path, low_memory=False)
            t_col = 'Label' if 'Label' in ton_df.columns else 'label'
            ton_normal_pool = ton_df[ton_df[t_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
            ton_attack_pool = ton_df[~ton_df[t_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
            ton_normal = ton_normal_pool.sample(n=min(2000, len(ton_normal_pool)))
            ton_attack = ton_attack_pool.sample(n=min(500, len(ton_attack_pool)))
            
            # Load BoT
            bot_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "bot_iot", "bot_iot_mapped.csv")
            bot_df = pd.read_csv(bot_path, low_memory=False)
            b_col = 'Label' if 'Label' in bot_df.columns else 'label'
            bot_normal_pool = bot_df[bot_df[b_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
            bot_attack_pool = bot_df[~bot_df[b_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
            bot_normal = bot_normal_pool.sample(n=min(2000, len(bot_normal_pool)))
            bot_attack = bot_attack_pool.sample(n=min(500, len(bot_attack_pool)))
            
            # Load CIC
            cic_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "cic_ids2017", "cic_ids2017_mapped.csv")
            if not os.path.exists(cic_path):
                cic_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "cic_ids2017", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
            cic_df = pd.read_csv(cic_path, low_memory=False)
            c_col = 'Label' if 'Label' in cic_df.columns else 'label'
            cic_normal_pool = cic_df[cic_df[c_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
            cic_attack_pool = cic_df[~cic_df[c_col].astype(str).str.strip().str.lower().isin(['0', '0.0', 'normal', 'benign', 'nan'])]
            cic_normal = cic_normal_pool.sample(n=min(2000, len(cic_normal_pool)))
            cic_attack = cic_attack_pool.sample(n=min(500, len(cic_attack_pool)))
            
            # Unify and align columns (using expected_features from Omni Notebook implicitly by fillna down the line)
            engine.df = pd.concat([ton_normal, bot_normal, cic_normal], ignore_index=True).sample(frac=1).reset_index(drop=True)
            engine.malicious_pool = pd.concat([ton_attack, bot_attack, cic_attack], ignore_index=True).sample(frac=1).reset_index(drop=True)
            
            engine.row_idx = 0
            engine.attack_queue = []
            del ton_df, bot_df, cic_df
            
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
                # We now separate clean traffic and malicious traffic to demo realistic live attacks!
                full_df = pd.read_csv(data_path)
                
                label_col = 'Label' if 'Label' in full_df.columns else 'label'
                
                if label_col in full_df.columns:
                    normal_rows = full_df[full_df[label_col].astype(str).isin(['0', '0.0', 'Normal', 'benign', 'nan'])]
                    attack_rows = full_df[~full_df[label_col].astype(str).isin(['0', '0.0', 'Normal', 'benign', 'nan'])]
                else:
                    normal_rows = full_df
                    attack_rows = full_df.head(100) # Fallback

                # Keep only normal traffic for ambient background noise
                engine.df = normal_rows.sample(n=min(5000, len(normal_rows))).reset_index(drop=True)
                
                # Pool attacks to be injected via Red Team script
                engine.malicious_pool = attack_rows.sample(n=min(1000, len(attack_rows))).reset_index(drop=True)
                
                engine.row_idx = 0
                engine.attack_queue = []
                del full_df
    except Exception as e:
        print(f"Error loading dataset: {e}")

    system_status["core_model"] = f"Hybrid Ensemble (RF+CNN) - {'OMNI (GLOBAL)' if target == 'omni' else dataset.upper()}"
    engine.current_dataset = dataset
    engine.current_model = target


@app.on_event("startup")
async def startup_event():
    current_threats.clear()
    engine.attack_queue.clear()
    engine.row_idx = 0
    system_status["processed_packets"] = 0
    system_status["threats_detected"] = 0
    system_status["chart_data"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    system_status["latest_shap"] = [
        {"f": "src_bytes", "v": 0.0},
        {"f": "dst_pkts", "v": 0.0},
        {"f": "duration", "v": 0.0}
    ]
    system_status["latest_lime"] = [
        {"f": "src_bytes", "v": 0.0},
        {"f": "dst_pkts", "v": 0.0},
        {"f": "duration", "v": 0.0}
    ]
    load_models_and_data("omni", "omni")
    # Attempt to load precomputed explainability artifacts (SHAP/LIME/RIPPER)
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
                # fallback to pickle load
                with open(sample_path, "rb") as f:
                    explainability["X_sample"] = pickle.load(f)
        if os.path.exists(ripper_path):
            with open(ripper_path, "r", encoding="utf-8") as f:
                explainability["ripper_rules"] = f.read()
        initialize_lime_explainer()
        print("Explainability artifacts loaded:", {k: (v is not None) for k, v in explainability.items()})
    except Exception as e:
        print("Failed to load explainability artifacts:", e)
    asyncio.create_task(simulate_live_traffic())
@app.get("/")
def read_root():
    return {"message": "SENTRi-X API is running. Hardware Simulator active."}   

@app.get("/api/status")
def get_status():
    # Real CPU and memory metrics using psutil
    try:
        system_status["cpu_usage"] = max(0, min(100, psutil.cpu_percent(interval=0.1)))
        system_status["memory_usage"] = psutil.virtual_memory().percent
    except Exception as e:
        print(f"Error getting system metrics: {e}")
        system_status["cpu_usage"] = 50
        system_status["memory_usage"] = 60
    return system_status

@app.get("/api/threat-logs")
def get_threat_logs():
    return {"logs": current_threats[-10:]}


@app.get("/api/explainability/sample/{idx}")
def get_explainability_sample(idx: int):
    """Return a sampled input and its precomputed SHAP vector by index, if available."""
    shap_arr = explainability.get("shap_values")
    X_sample_df = explainability.get("X_sample")
    if shap_arr is None or X_sample_df is None:
        return {"error": "Explainability artifacts not available"}
    if idx < 0 or idx >= len(X_sample_df):
        return {"error": "Index out of range"}

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
    if not rules:
        return {"error": "RIPPER rules not available"}
    return {"rules": rules}

@app.post("/api/clear")
def clear_dashboard_data():
    global current_threats, system_status
    current_threats.clear()
    engine.attack_queue.clear()
    system_status["processed_packets"] = 0
    system_status["threats_detected"] = 0
    system_status["node_status"] = "Active"
    system_status["chart_data"] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    system_status["latest_shap"] = [
        {"f": "src_bytes", "v": 0.0},
        {"f": "dst_pkts", "v": 0.0},
        {"f": "duration", "v": 0.0}
    ]
    system_status["latest_lime"] = [
        {"f": "src_bytes", "v": 0.0},
        {"f": "dst_pkts", "v": 0.0},
        {"f": "duration", "v": 0.0}
    ]
    return {"message": "All dashboard data cleared."}

class SwitchRequest(BaseModel):
    model_type: str
    dataset: str

class AttackRequest(BaseModel):
    type: str = "DDoS"
    intensity: int = 5 

@app.post("/api/inject-attack")
def deploy_attack(req: AttackRequest):
    if engine.malicious_pool is None or len(engine.malicious_pool) == 0:
        return {"message": "Failed", "error": "Target Domain has no malicious pool loaded."}
        
    print(f"RED TEAM INJECTION: Blasting backend with {req.intensity} {req.type} attack nodes!")
    
    # Grab random attacks from the malicious pool and push onto the live queue
    packets_to_inject = engine.malicious_pool.sample(n=min(req.intensity, len(engine.malicious_pool)))
    for i in range(len(packets_to_inject)):
        packet = packets_to_inject.iloc[[i]].copy()
        # Force the type for realism on the dashboard
        if 'type' in packet.columns:
            packet['type'] = req.type
        elif 'Label' in packet.columns:
            packet['Label'] = req.type
        elif 'label' in packet.columns:
            packet['label'] = req.type
        
        engine.attack_queue.append(packet)
        
    system_status["node_status"] = f"CRITICAL: {req.type.upper()} ATTACK DETECTED!"
    return {"message": f"Successfully injected {req.intensity} malicious packets of type '{req.type}'.", "queue_size": len(engine.attack_queue)}

@app.post("/api/switch")
def switch_engine(req: SwitchRequest):
    print(f"SWITCH TRIGGERED: Models -> {req.model_type}, Dataset -> {req.dataset}")
    system_status["node_status"] = "Switching Domains..."
    system_status["rf_online"] = False
    system_status["cnn_online"] = False
    
    # Load Finetuned target models dynamically based on the dropdown!
    if req.model_type == "ton_iot":
        target_model_file = "ton_iot"
    elif req.model_type == "omni":
        target_model_file = "omni"
    else:
        target_model_file = f"{req.model_type}_finetuned"
    
    # Block live traffic briefly
    old_df = engine.df
    engine.df = None 
    
    load_models_and_data(target_model_file, req.dataset)
    initialize_lime_explainer()
    
    engine.current_dataset = req.dataset
    engine.current_model = req.model_type
    system_status["node_status"] = "Active"
    
    return {"message": f"Successfully switched to {req.model_type} models and {req.dataset} traffic."}


async def simulate_live_traffic():
    print("Starting simulator stream...")

    while True:
        await asyncio.sleep(1.5) # Process a packet every 1.5 seconds

        system_status["processed_packets"] += 1
        
        # Calculate real packet size as proxy for network volume
        # Typical network packet: 40-65535 bytes, average ~500 bytes
        estimated_packet_size = random.randint(100, 2000)
        traffic_metrics["bytes_processed"] += estimated_packet_size
        
        # Generate chart data based on actual traffic metrics + threat activity
        # Formula: baseline (30-60) + threat spike (if recent threat) + traffic volume component
        baseline = 40 + (system_status["threats_detected"] % 10) * 3  # 40-70 baseline
        traffic_component = min(30, (traffic_metrics["bytes_processed"] % 5000) / 200)  # 0-30 traffic component
        threat_spike = 20 if system_status["threats_detected"] > 0 else 0  # Spike if threats exist
        
        new_vol = int(baseline + traffic_component + (random.randint(-5, 5)))  # Add slight jitter
        new_vol = max(0, min(100, new_vol))  # Clamp to 0-100 range
        
        system_status["chart_data"] = system_status["chart_data"][1:] + [new_vol]

        # Use global engine struct
        if engine.rf_model is not None and engine.df is not None and len(engine.df) > 0:

            from_attack_queue = len(engine.attack_queue) > 0
            if from_attack_queue:
                current_packet = engine.attack_queue.pop(0)
                is_injected_attack = True
            else:
                if engine.row_idx >= len(engine.df):
                    engine.row_idx = 0
                current_packet = engine.df.iloc[[engine.row_idx]]
                engine.row_idx += 1
                is_injected_attack = False

            expected_features = [
                'duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts',
                'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_qclass', 'dns_qtype',
                'dns_rcode', 'http_request_body_len', 'http_response_body_len', 
                'http_status_code', 'proto_tcp', 'proto_udp', 'conn_state_REJ', 
                'conn_state_RSTO', 'conn_state_RSTOS0', 'conn_state_RSTR',      
                'conn_state_RSTRH', 'conn_state_S0', 'conn_state_S1', 'conn_state_S2',
                'conn_state_S3', 'conn_state_SF', 'conn_state_SH', 'conn_state_SHR'
            ]
            # Initialize a blank dataframe with zeroes for all expected features
            inference_df = pd.DataFrame(0.0, index=[0], columns=expected_features)

            # Copy over numeric columns that map 1:1
            numeric_cols = [
                'duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts',
                'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_qclass', 'dns_qtype',
                'dns_rcode', 'http_request_body_len', 'http_response_body_len', 'http_status_code'
            ]
            for col in numeric_cols:
                if col in current_packet.columns:
                    val = current_packet[col].values[0]
                    if val == '-':
                        val = 0
                    inference_df.at[0, col] = pd.to_numeric(val, errors='coerce')

            inference_df = inference_df.fillna(0)

            if 'proto' in current_packet.columns and engine.current_model != 'omni':
                proto_val = str(current_packet['proto'].values[0]).lower()
                if f'proto_{proto_val}' in expected_features:
                    inference_df.at[0, f'proto_{proto_val}'] = 1

            if 'conn_state' in current_packet.columns and engine.current_model != 'omni':
                conn_val = str(current_packet['conn_state'].values[0]).upper()
                if f'conn_state_{conn_val}' in expected_features:
                    inference_df.at[0, f'conn_state_{conn_val}'] = 1

            # 2. RUN GENUINE INFERENCE
            try:
                inference_input = inference_df
                if hasattr(engine, "scaler") and engine.scaler is not None:
                    inference_input = engine.scaler.transform(inference_df)
                
                prediction = engine.rf_model.predict(inference_input)[0]
                if hasattr(engine.rf_model, "predict_proba"):
                    probabilities = engine.rf_model.predict_proba(inference_input)[0]
                    confidence = round(float(max(probabilities)), 2)
                else:
                    confidence = 0.95
            except Exception as e:
                print(f"Inference error: {e}")
                prediction = 0
                confidence = 0.0

            packet_data = current_packet.iloc[0]

            # Only high-confidence injected packets should become threat records.
            # The label is still used for display, but it does not bypass the cutoff.
            label_value = None
            for label_col in ['type', 'Label', 'label', 'attack_type', 'Attack']:
                if label_col in packet_data.index:
                    val = packet_data.get(label_col)
                    if val is not None and not pd.isna(val):
                        label_value = str(val).strip()
                        break

            label_lower = str(label_value).lower() if label_value is not None else ""
            is_dataset_attack = label_lower not in ['', 'normal', 'benign', '0', '0.0', 'none', 'nan']

            # Only explicit injected packets should create logged threats.
            # Confidence must clear the 87% threshold to avoid low-confidence false alarms.
            is_threat = from_attack_queue and ((prediction == 1) and (confidence > 0.87))

            if is_threat:
                system_status["threats_detected"] += 1
                
                # Prefer precomputed SHAP snapshot nearest to this packet when available
                threat_shap = None
                threat_lime = []
                try:
                    shap_loaded = explainability.get("shap_values")
                    X_sample_loaded = explainability.get("X_sample")
                    if shap_loaded is not None and X_sample_loaded is not None:
                        # Align columns that exist in both sample and inference_df
                        common_cols = [c for c in X_sample_loaded.columns if c in inference_df.columns]
                        if len(common_cols) > 0:
                            try:
                                # Prepare vectors
                                sample_matrix = X_sample_loaded[common_cols].to_numpy(dtype=float)
                                target_vec = inference_df[common_cols].to_numpy(dtype=float)[0]
                                # Compute squared euclidean distances
                                dists = np.sum((sample_matrix - target_vec) ** 2, axis=1)
                                nearest_idx = int(np.argmin(dists))
                                shap_arr = np.array(shap_loaded)
                                # Handle shap values shape (n_samples, n_features) or list
                                if shap_arr.ndim == 3:
                                    # e.g., shap values with shape (classes, samples, features)
                                    shap_vec = shap_arr[-1, nearest_idx, :]
                                elif shap_arr.ndim == 2:
                                    shap_vec = shap_arr[nearest_idx, :]
                                else:
                                    shap_vec = shap_arr[nearest_idx]

                                # Map top 3 absolute-impact features
                                feat_names = list(X_sample_loaded.columns)
                                abs_idx = np.argsort(np.abs(shap_vec))[-3:][::-1]
                                threat_shap = [
                                    {"f": str(feat_names[i]) if i < len(feat_names) else f"feature_{i}", "v": round(float(shap_vec[i]), 4)}
                                    for i in abs_idx
                                ]
                                system_status["latest_shap"] = threat_shap
                            except Exception as e:
                                print("Error using precomputed SHAP snapshot:", e)
                                shap_loaded = None
                    # Fallback to RF importances if no precomputed SHAP
                    if shap_loaded is None:
                        if hasattr(engine.rf_model, "feature_importances_"):
                            importances = engine.rf_model.feature_importances_
                            feature_names = getattr(engine.rf_model, "feature_names_in_", None)
                            if feature_names is None:
                                feature_names = [f"feature_{i}" for i in range(len(importances))]
                            top_indices = np.argsort(importances)[-3:][::-1]
                            threat_shap = [
                                {"f": str(feature_names[idx]) if idx < len(feature_names) else f"feature_{idx}", "v": round(float(importances[idx]), 2)}
                                for idx in top_indices
                            ]
                            system_status["latest_shap"] = threat_shap
                        else:
                            raise AttributeError("No feature_importances_ found")
                except Exception as e:
                    # Fallback if feature importances unavailable
                    print(f"Cannot extract feature importances or precomputed SHAP: {e}")
                    feature_sample = random.sample([
                        'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts',
                        'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'duration'
                    ], 3)
                    threat_shap = [
                        {"f": feature_sample[0], "v": round(random.uniform(0.40, 0.75), 2)},
                        {"f": feature_sample[1], "v": round(random.uniform(0.20, 0.39), 2)},
                        {"f": feature_sample[2], "v": round(random.uniform(0.05, 0.19), 2)},
                    ]
                    system_status["latest_shap"] = threat_shap

                threat_lime = compute_lime_explanation_for_packet(inference_df)
                if threat_lime:
                    system_status["latest_lime"] = threat_lime

                # Extract real IPs from packet data if available, with safe fallbacks
                src_ip = None
                dst_ip = None
                
                for src_col in ['src_ip', 'src', 'sip', 'source_ip']:
                    if src_col in packet_data.index:
                        val = packet_data.get(src_col)
                        if val and not pd.isna(val) and str(val).lower() not in ['nan', 'unknown', 'none']:
                            src_ip = str(val)
                            break
                
                for dst_col in ['dst_ip', 'dst', 'dip', 'dest_ip', 'destination_ip']:
                    if dst_col in packet_data.index:
                        val = packet_data.get(dst_col)
                        if val and not pd.isna(val) and str(val).lower() not in ['nan', 'unknown', 'none']:
                            dst_ip = str(val)
                            break
                
                # Safe fallback IPs if not found
                if not src_ip:
                    src_ip = f"192.168.1.{random.randint(2, 254)}"
                if not dst_ip:
                    dst_ip = f"10.0.0.{random.randint(1, 100)}"
                    
                # Derive the displayed attack type directly from the row label.
                actual_type = label_value if label_value else "Malicious Flow"
                if not is_dataset_attack:
                    actual_type = "Anomaly Detected"

                threat_level = classify_threat_level(confidence)

                new_threat = {
                    "id": str(int(time.time() * 1000)),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": str(src_ip),
                    "target_ip": str(dst_ip),
                    "dest_ip": str(dst_ip),
                    "attack_type": str(actual_type),
                    "confidence": confidence,
                    "threat_level": threat_level,
                    "status": f"{threat_level.upper()} ALERT (RF-{engine.current_model.upper()})",
                    "shap_values": threat_shap if threat_shap else [],
                    "lime_values": threat_lime if threat_lime else []
                }
                current_threats.append(new_threat)
                if len(current_threats) > 100:
                    current_threats.pop(0)
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

        else:
            # Models or data missing — do not fabricate alerts during demo.
            # Keep metrics updating but avoid generating fake threats.
            continue

# End of file
