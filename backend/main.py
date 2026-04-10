from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import random
import time
import asyncio
import joblib
import os

app = FastAPI(title="SENTRi-X Backend API", description="Data Simulator for 50% Thesis Defense")

# Allow the React frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://localhost:5175", "http://127.0.0.1:5175"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables to hold simulated state
current_threats = []
system_status = {
    "node_status": "Active",
    "core_model": "Hybrid Ensemble (RF+CNN)",
    "processed_packets": 0,
    "threats_detected": 0,
    "cpu_usage": 45,
    "memory_usage": 60,
}

@app.get("/")
def read_root():
    return {"message": "SENTRi-X API is running. Hardware Simulator active."}

@app.get("/api/status")
def get_status():
    """Return the current system status for the dashboard header and cards."""
    # Add slight random variation to simulate live metrics
    system_status["cpu_usage"] = random.randint(30, 80)
    system_status["memory_usage"] = random.randint(50, 90)
    return system_status

@app.get("/api/threat-logs")
def get_threat_logs():
    """Return the most recent simulated threat logs."""
    return {"logs": current_threats[-10:]} # Return top 10 recent threats

# This function reads live packets from the CSV and runs them through the model
async def simulate_live_traffic():
    print("Loading Random Forest Model...")
    
    # Path to the actual model
    model_path = os.path.join(os.path.dirname(__file__), "..", "models", "rf_model_ton_iot.joblib")
    
    # Check if model exists before trying to load it
    rf_model = None
    if os.path.exists(model_path):
        try:
            rf_model = joblib.load(model_path)
            print(f"Successfully loaded model from {model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
    else:
        print(f"WARNING: Model not found at {model_path}. Falling back to mock data.")

    # Path to the raw dataset to stream from
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "ton_iot", "Network_dataset_1.csv")
    
    df = None
    if os.path.exists(data_path):
        print(f"Loading stream dataset from {data_path}...")
        try:
            # We just load 1000 rows to simulate with so we don't melt memory during testing
            df = pd.read_csv(data_path, nrows=1000) 
            print(f"Dataset loaded with {len(df)} simulated packets.")
        except Exception as e:
             print(f"Error loading dataset: {e}")
    else:
         print(f"WARNING: Dataset not found at {data_path}. Falling back to mock data.")

    print("Starting simulator stream...")
    
    row_idx = 0
    while True:
        await asyncio.sleep(1.5) # Process a packet every 1.5 seconds
        
        system_status["processed_packets"] += 1
        
        # If we have both the model and the data, do REAL inference!
        if rf_model is not None and df is not None and len(df) > 0:
            
            # Get the current row (simulating an incoming packet)
            if row_idx >= len(df):
                row_idx = 0
                
            current_packet = df.iloc[[row_idx]] # Keep as dataframe for model
            row_idx += 1
            
            # 1. Feature Engineering for Inference
            # The model expects these exact 28 features based on training:
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
            inference_df = pd.DataFrame(0, index=[0], columns=expected_features)
            
            # Copy over numeric columns that map 1:1
            numeric_cols = [
                'duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts',
                'src_ip_bytes', 'dst_pkts', 'dst_ip_bytes', 'dns_qclass', 'dns_qtype',
                'dns_rcode', 'http_request_body_len', 'http_response_body_len', 'http_status_code'
            ]
            for col in numeric_cols:
                if col in current_packet.columns:
                    # Handle any nulls or string hyphens '-' commonly found in networking datasets
                    val = current_packet[col].values[0]
                    if val == '-':
                        val = 0
                    inference_df.at[0, col] = pd.to_numeric(val, errors='coerce')
            
            inference_df = inference_df.fillna(0) # Ensure no NaNs before inference
            
            # Map Categorical column 'proto' to one-hot structure
            if 'proto' in current_packet.columns:
                proto_val = str(current_packet['proto'].values[0]).lower()
                if f'proto_{proto_val}' in expected_features:
                    inference_df.at[0, f'proto_{proto_val}'] = 1
                    
            # Map Categorical column 'conn_state' to one-hot structure
            if 'conn_state' in current_packet.columns:
                conn_val = str(current_packet['conn_state'].values[0]).upper()
                if f'conn_state_{conn_val}' in expected_features:
                    inference_df.at[0, f'conn_state_{conn_val}'] = 1

            # 2. RUN GENUINE INFERENCE
            try:
                # The model returns an array, [0] gets the single prediction
                prediction = rf_model.predict(inference_df)[0]
                
                # Check confidence probabilities (usually [prob_normal, prob_attack])
                if hasattr(rf_model, "predict_proba"):
                    probabilities = rf_model.predict_proba(inference_df)[0]
                    confidence = round(float(max(probabilities)), 2)
                else:
                    confidence = 0.95
                    
            except Exception as e:
                print(f"Inference error: {e}")
                prediction = 0
                confidence = 0.0

            # 3. Analyze the ML Prediction
            # In the ToN-IoT dataset labels: 0 is Normal, 1 is Attack
            is_threat = (prediction == 1)
            
            if is_threat:
                system_status["threats_detected"] += 1
                
                # Fetch metadata to display on the dashboard (we pull this from the RAW packet, not the ML features)
                packet_data = current_packet.iloc[0]
                src_ip = packet_data.get('src_ip', f"Unknown")
                dst_ip = packet_data.get('dst_ip', f"Unknown")
                # The dataset often has the ground-truth "type" which we use just for labeling the UI if it exists
                actual_type = packet_data.get('type', 'Malicious Flow')
                if str(actual_type) == 'normal' or str(actual_type) == 'nan':
                    actual_type = "Anomaly Detected"
                
                new_threat = {
                    "id": str(int(time.time() * 1000)),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": str(src_ip),
                    "dest_ip": str(dst_ip),
                    "attack_type": str(actual_type),
                    "confidence": confidence,
                    "action_taken": "Dropped via ML Engine"
                }
                current_threats.append(new_threat)
                if len(current_threats) > 100:
                    current_threats.pop(0)

        else:
            # Only fires if the ML model literally didn't load (fallback so the backend doesn't crash)
            if random.random() < 0.1:
                system_status["threats_detected"] += 1
                new_threat = {
                    "id": str(int(time.time() * 1000)),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": f"192.168.1.{random.randint(2,254)}",
                    "dest_ip": f"10.0.0.{random.randint(1,100)}",
                    "attack_type": random.choice(["DDoS", "PortScan", "Infiltration", "Botnet"]),
                    "confidence": round(random.uniform(0.85, 0.99), 2),
                    "action_taken": "Blocked (Mock)"
                }
                current_threats.append(new_threat)
                if len(current_threats) > 100:
                    current_threats.pop(0)

@app.on_event("startup")
async def startup_event():
    # Start the background simulator task when the server starts
    asyncio.create_task(simulate_live_traffic())
