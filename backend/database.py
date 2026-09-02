import sqlite3
import os
import json
import time
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sentrix.db")


def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the SQLite database matching Thesis Chapter 3 Figure 5 schema."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Network_Flows Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Network_Flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP NOT NULL,
        sensor_id TEXT DEFAULT 'rpi3b-edge-01',
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        proto TEXT DEFAULT 'TCP',
        duration REAL DEFAULT 0.0,
        src_bytes INTEGER DEFAULT 0,
        dst_bytes INTEGER DEFAULT 0,
        src_pkts INTEGER DEFAULT 0,
        dst_pkts INTEGER DEFAULT 0,
        is_anomaly INTEGER DEFAULT 0,
        model_used TEXT DEFAULT 'omni',
        confidence REAL DEFAULT 0.0
    );
    """)

    # 3. Alert_Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Alert_Logs (
        id TEXT PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL,
        source_ip TEXT NOT NULL,
        target_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        confidence REAL NOT NULL,
        threat_level TEXT NOT NULL,
        status TEXT NOT NULL,
        model_type TEXT DEFAULT 'omni',
        execution_mode TEXT DEFAULT 'hybrid',
        shap_values TEXT, -- JSON Array
        lime_values TEXT, -- JSON Array
        raw_payload TEXT  -- JSON Object
    );
    """)

    # Default Admin User if not exists
    cursor.execute("SELECT id FROM Users WHERE username = 'admin';")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO Users (username, password_hash, role)
        VALUES ('admin', 'sentrix_admin_sha256', 'SOC Lead');
        """)

    conn.commit()
    conn.close()
    print(f"Database initialized at: {os.path.abspath(DB_PATH)}")


def insert_network_flow(
    src_ip: str,
    dst_ip: str,
    proto: str = "TCP",
    duration: float = 0.0,
    src_bytes: int = 0,
    dst_bytes: int = 0,
    src_pkts: int = 0,
    dst_pkts: int = 0,
    is_anomaly: int = 0,
    model_used: str = "omni",
    confidence: float = 0.0,
    sensor_id: str = "rpi3b-edge-01"
) -> int:
    """Logs a single traffic flow into the Network_Flows table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
    INSERT INTO Network_Flows (
        timestamp, sensor_id, src_ip, dst_ip, proto, duration,
        src_bytes, dst_bytes, src_pkts, dst_pkts, is_anomaly,
        model_used, confidence
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        ts, sensor_id, src_ip, dst_ip, proto, duration,
        src_bytes, dst_bytes, src_pkts, dst_pkts, is_anomaly,
        model_used, confidence
    ))
    flow_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return flow_id


def insert_alert(threat: Dict[str, Any]):
    """Persistently stores a detected threat and its XAI parameters into Alert_Logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    threat_id = str(threat.get("id", str(int(time.time() * 1000))))
    ts = threat.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    src_ip = str(threat.get("source_ip", "192.168.1.100"))
    dst_ip = str(threat.get("target_ip") or threat.get("dest_ip") or "10.0.0.1")
    attack_type = str(threat.get("attack_type", "Malicious Flow Anomaly"))
    confidence = float(threat.get("confidence", 0.0))
    threat_level = str(threat.get("threat_level", "medium"))
    status = str(threat.get("status", "ACTIVE ALERT"))
    model_type = str(threat.get("model_type", "omni"))
    execution_mode = str(threat.get("execution_mode", "hybrid"))
    shap_json = json.dumps(threat.get("shap_values", []))
    lime_json = json.dumps(threat.get("lime_values", []))
    raw_payload = json.dumps(threat.get("raw_payload", {}))

    cursor.execute("""
    INSERT OR REPLACE INTO Alert_Logs (
        id, timestamp, source_ip, target_ip, dest_ip, attack_type,
        confidence, threat_level, status, model_type, execution_mode,
        shap_values, lime_values, raw_payload
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        threat_id, ts, src_ip, dst_ip, dst_ip, attack_type,
        confidence, threat_level, status, model_type, execution_mode,
        shap_json, lime_json, raw_payload
    ))
    conn.commit()
    conn.close()


def get_all_alerts(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieves the most recent alerts from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM Alert_Logs ORDER BY timestamp DESC LIMIT ?;
    """, (limit,))
    rows = cursor.fetchall()
    
    alerts = []
    for r in rows:
        alerts.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "source_ip": r["source_ip"],
            "target_ip": r["target_ip"],
            "dest_ip": r["dest_ip"],
            "attack_type": r["attack_type"],
            "confidence": r["confidence"],
            "threat_level": r["threat_level"],
            "status": r["status"],
            "model_type": r["model_type"],
            "execution_mode": r["execution_mode"],
            "shap_values": json.loads(r["shap_values"]) if r["shap_values"] else [],
            "lime_values": json.loads(r["lime_values"]) if r["lime_values"] else [],
        })
    conn.close()
    return alerts


def clear_all_alerts():
    """Clears the Alert_Logs table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Alert_Logs;")
    conn.commit()
    conn.close()


def get_database_stats() -> Dict[str, Any]:
    """Returns database size and record counts for SOC telemetry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as count FROM Network_Flows;")
    flows_count = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM Alert_Logs;")
    alerts_count = cursor.fetchone()["count"]
    
    cursor.execute("SELECT attack_type, COUNT(*) as cnt FROM Alert_Logs GROUP BY attack_type;")
    attack_breakdown = {r["attack_type"]: r["cnt"] for r in cursor.fetchall()}
    
    conn.close()
    
    db_size_kb = 0.0
    if os.path.exists(DB_PATH):
        db_size_kb = round(os.path.getsize(DB_PATH) / 1024.0, 2)
        
    return {
        "db_path": os.path.abspath(DB_PATH),
        "db_size_kb": db_size_kb,
        "total_flows_logged": flows_count,
        "total_alerts_logged": alerts_count,
        "attack_breakdown": attack_breakdown
    }
