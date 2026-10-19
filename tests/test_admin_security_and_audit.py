import json
import os
from pathlib import Path
import sqlite3
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_security.db"
    monkeypatch.setattr("database.DB_PATH", str(db_file))
    import database
    database.init_db()
    return database


def test_database_audit_log_crud_and_pruning(isolated_db):
    # Insert audit logs
    id1 = isolated_db.insert_audit_log(
        actor="admin",
        action="UPDATE_SETTINGS",
        resource="settings",
        details=json.dumps({"alert_threshold": 0.65}),
        client_ip="192.168.1.100",
        status="SUCCESS"
    )
    assert id1 > 0

    id2 = isolated_db.insert_audit_log(
        actor="unauthenticated",
        action="ACCESS_DENIED:PUT:/api/settings",
        resource="/api/settings",
        details="Missing API key",
        client_ip="10.0.0.5",
        status="DENIED"
    )
    assert id2 > id1

    # Query logs
    logs = isolated_db.get_audit_logs(limit=10)
    assert len(logs) == 2
    assert logs[0]["id"] == id2  # newest first
    assert logs[0]["status"] == "DENIED"
    assert logs[0]["client_ip"] == "10.0.0.5"
    assert logs[1]["status"] == "SUCCESS"
    assert logs[1]["action"] == "UPDATE_SETTINGS"

    # Filter by action
    denied_logs = isolated_db.get_audit_logs(action="ACCESS_DENIED:PUT:/api/settings")
    assert len(denied_logs) == 1
    assert denied_logs[0]["actor"] == "unauthenticated"

    # Test max records pruning
    for i in range(15):
        isolated_db.insert_audit_log("admin", f"ACTION_{i}", "res")
    assert len(isolated_db.get_audit_logs(limit=50)) == 17
    deleted = isolated_db.prune_audit_logs(retention_days=365, max_records=5)
    assert deleted == 12
    assert len(isolated_db.get_audit_logs(limit=50)) == 5


def test_admin_api_key_persistence(isolated_db):
    key = isolated_db.get_or_set_admin_api_key()
    assert key is not None and len(key) >= 8

    # Update key
    updated = isolated_db.get_or_set_admin_api_key("custom-secret-key-12345")
    assert updated == "custom-secret-key-12345"
    assert isolated_db.get_or_set_admin_api_key() == "custom-secret-key-12345"


def test_api_auth_enforcement_and_audit_attribution(tmp_path, monkeypatch):
    db_file = tmp_path / "test_auth_api.db"
    monkeypatch.setattr("database.DB_PATH", str(db_file))
    monkeypatch.setenv("SENTRIX_REQUIRE_AUTH", "true")
    monkeypatch.setenv("SENTRIX_ADMIN_KEY", "test-secret-admin-key-2026")

    import database
    database.init_db()

    import main
    # Ensure fresh state
    client = TestClient(main.app)

    # 1. Unauthenticated mutation request should fail with 401
    res_unauth = client.put("/api/settings", json={"active_alerting": True, "alert_threshold": 0.6})
    assert res_unauth.status_code == 401
    assert "Admin authentication required" in res_unauth.json()["detail"]

    # 2. Check that DENIED event was recorded in audit logs
    denied_logs = database.get_audit_logs(limit=5)
    assert len(denied_logs) >= 1
    assert denied_logs[0]["status"] == "DENIED"
    assert denied_logs[0]["actor"] == "unauthenticated"

    # 3. Invalid API key should fail with 401
    res_invalid = client.put(
        "/api/settings",
        json={"active_alerting": True, "alert_threshold": 0.6},
        headers={"X-API-Key": "wrong-key"}
    )
    assert res_invalid.status_code == 401

    # 4. Valid X-API-Key should succeed and record SUCCESS audit log
    res_valid = client.put(
        "/api/settings",
        json={"active_alerting": True, "alert_threshold": 0.75},
        headers={"X-API-Key": "test-secret-admin-key-2026"}
    )
    assert res_valid.status_code == 200
    assert res_valid.json()["alert_threshold"] == 0.75

    audit_logs = database.get_audit_logs(limit=10)
    success_event = next(log for log in audit_logs if log["action"] == "UPDATE_SETTINGS")
    assert success_event["status"] == "SUCCESS"
    assert success_event["actor"] == "admin"
    assert "0.75" in success_event["details"]

    # 5. Device enrollment with Bearer token authorization
    res_dev = client.post(
        "/api/monitored-devices",
        json={"mac": "aa:bb:cc:dd:ee:ff", "name": "Test Cam"},
        headers={"Authorization": "Bearer test-secret-admin-key-2026"}
    )
    assert res_dev.status_code == 200
    dev_event = next(log for log in database.get_audit_logs(limit=10) if log["action"] == "ADD_MONITORED_DEVICE")
    assert dev_event["status"] == "SUCCESS"
    assert "aa:bb:cc:dd:ee:ff" in dev_event["resource"]

    # 6. Audit logs endpoint itself is protected
    res_audit_unauth = client.get("/api/admin/audit-logs")
    assert res_audit_unauth.status_code == 401

    res_audit_auth = client.get(
        "/api/admin/audit-logs",
        headers={"X-API-Key": "test-secret-admin-key-2026"}
    )
    assert res_audit_auth.status_code == 200
    assert "logs" in res_audit_auth.json()
    assert len(res_audit_auth.json()["logs"]) >= 3
