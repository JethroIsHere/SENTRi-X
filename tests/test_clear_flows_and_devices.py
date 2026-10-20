import json
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def clean_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_clear.db"
    monkeypatch.setattr("database.DB_PATH", str(db_file))
    monkeypatch.setenv("SENTRIX_REQUIRE_AUTH", "true")
    monkeypatch.setenv("SENTRIX_ADMIN_KEY", "test-admin-key-2026")
    import database
    database.init_db()
    return database


def test_clear_all_flows_and_device_observations_database(clean_db):
    # Insert test flows with and without device identities
    clean_db.insert_network_flow("192.168.1.10", "192.168.1.1", "TCP", data_source="live_hardware")
    clean_db.insert_network_flow(
        "192.168.1.20", "192.168.1.1", "UDP",
        data_source="live_hardware", device_name="TestPlug", device_mac="aa:bb:cc:11:22:33"
    )
    clean_db.insert_network_flow(
        "192.168.1.30", "192.168.1.1", "TCP",
        data_source="live_hardware", device_name="TestCam", device_mac="dd:ee:ff:44:55:66"
    )

    flows = clean_db.get_recent_flows(limit=10)
    assert len(flows) == 3
    devices = clean_db.get_device_summaries()
    assert len(devices) == 2

    # Clear single device
    clean_db.clear_device_observations("aa:bb:cc:11:22:33")
    devices = clean_db.get_device_summaries()
    assert len(devices) == 1
    assert devices[0]["device_mac"] == "dd:ee:ff:44:55:66"

    # Clear remaining device observations
    clean_db.clear_device_observations()
    devices = clean_db.get_device_summaries()
    assert len(devices) == 0

    # Non-device flow is still present
    flows = clean_db.get_recent_flows(limit=10)
    assert len(flows) == 1

    # Clear all flows
    clean_db.clear_all_flows()
    flows = clean_db.get_recent_flows(limit=10)
    assert len(flows) == 0


def test_clear_endpoints_auth_and_audit(clean_db):
    import main
    client = TestClient(main.app)

    # Populate data
    clean_db.insert_network_flow(
        "192.168.1.50", "192.168.1.1", "TCP",
        data_source="live_hardware", device_name="SmartSensor", device_mac="11:22:33:44:55:66"
    )

    # 1. Unauthenticated requests to /api/clear-flows and /api/clear-devices should return 401
    res1 = client.post("/api/clear-flows")
    assert res1.status_code == 401

    res2 = client.post("/api/clear-devices")
    assert res2.status_code == 401

    # 2. Authenticated clear-devices
    res_dev = client.post(
        "/api/clear-devices",
        json={"mac": "11:22:33:44:55:66"},
        headers={"X-API-Key": "test-admin-key-2026"}
    )
    assert res_dev.status_code == 200
    assert "Device observations reset" in res_dev.json()["message"]

    # Verify audit log
    audit_logs = clean_db.get_audit_logs(limit=5)
    dev_log = next(log for log in audit_logs if log["action"] == "CLEAR_OBSERVED_DEVICES")
    assert dev_log["status"] == "SUCCESS"
    assert "11:22:33:44:55:66" in dev_log["resource"]

    # 3. Authenticated clear-flows
    clean_db.insert_network_flow("10.0.0.1", "10.0.0.2", "TCP", data_source="live_hardware")
    res_flow = client.post(
        "/api/clear-flows",
        headers={"X-API-Key": "test-admin-key-2026"}
    )
    assert res_flow.status_code == 200
    assert "Live flows cleared successfully" in res_flow.json()["message"]

    flow_log = next(log for log in clean_db.get_audit_logs(limit=5) if log["action"] == "CLEAR_LIVE_FLOWS")
    assert flow_log["status"] == "SUCCESS"
    assert flow_log["resource"] == "Network_Flows"
