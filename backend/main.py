from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import random
import time
import asyncio

app = FastAPI(title="SENTRi-X Backend API", description="Data Simulator for 50% Thesis Defense")

# Allow the React frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"], # Common Vite/React dev ports
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

# This function simulates reading live packets and running them through the model
async def simulate_live_traffic():
    # In a real scenario, this would read from the CSV and call the joblib model
    print("Starting simulator...")
    while True:
        await asyncio.sleep(2) # Simulate processing a packet every 2 seconds
        
        system_status["processed_packets"] += 1
        
        # 10% chance to generate a random "threat" for the demo
        if random.random() < 0.1:
            system_status["threats_detected"] += 1
            new_threat = {
                "id": str(int(time.time() * 1000)),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": f"192.168.1.{random.randint(2,254)}",
                "dest_ip": f"10.0.0.{random.randint(1,100)}",
                "attack_type": random.choice(["DDoS", "PortScan", "Infiltration", "Botnet"]),
                "confidence": round(random.uniform(0.85, 0.99), 2),
                "action_taken": "Blocked"
            }
            current_threats.append(new_threat)
            # Keep log size manageable
            if len(current_threats) > 100:
                current_threats.pop(0)

@app.on_event("startup")
async def startup_event():
    # Start the background simulator task when the server starts
    asyncio.create_task(simulate_live_traffic())
