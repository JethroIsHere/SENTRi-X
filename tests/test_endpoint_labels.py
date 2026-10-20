import json
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def test_env(tmp_path, monkeypatch):
    db_file = tmp_path / "test_labels.db"
    monkeypatch.setattr("database.DB_PATH", str(db_file))
    monkeypatch.setenv("SENTRIX_REQUIRE_AUTH", "true")
    monkeypatch.setenv("SENTRIX_ADMIN_KEY", "test-admin-key-2026")
    import database
    database.init_db()
    return database


def test_endpoint_labels_database_defaults_and_crud(test_env):
    # Verify default labels are populated
    defaults = test_env.get_endpoint_labels()
    assert "192.168.254.184" in defaults
    assert defaults["192.168.254.184"] == "Raspberry Pi 3B+ Sensor"
    assert defaults["192.168.254.254"] == "Local Gateway / Router"
    assert defaults["192.168.254.156"] == "Defender Host (Laptop)"

    # Add custom label
    test_env.set_endpoint_label("192.168.254.99", "Kali Linux Attacker VM")
    labels = test_env.get_endpoint_labels()
    assert labels["192.168.254.99"] == "Kali Linux Attacker VM"

    # Update existing label
    test_env.set_endpoint_label("192.168.254.99", "Test Kali Machine")
    labels = test_env.get_endpoint_labels()
    assert labels["192.168.254.99"] == "Test Kali Machine"

    # Remove label
    removed = test_env.remove_endpoint_label("192.168.254.99")
    assert removed is True
    labels = test_env.get_endpoint_labels()
    assert "192.168.254.99" not in labels

    # Remove non-existent returns False
    assert test_env.remove_endpoint_label("192.168.254.99") is False


def test_endpoint_labels_api(test_env, monkeypatch):
    monkeypatch.setattr("backend.main.get_or_set_admin_api_key", lambda key=None: "test-admin-key-2026")
    from backend.main import app
    client = TestClient(app)

    # 1. Unauthenticated GET is public
    res = client.get("/api/endpoint-labels")
    assert res.status_code == 200
    data = res.json()
    assert "labels" in data
    assert "192.168.254.184" in data["labels"]

    # 2. Unauthenticated POST fails (401)
    res = client.post("/api/endpoint-labels", json={"ip": "10.0.0.5", "label": "Office Switch"})
    assert res.status_code == 401

    # 3. Authenticated POST succeeds
    res = client.post(
        "/api/endpoint-labels",
        headers={"X-API-Key": "test-admin-key-2026"},
        json={"ip": "10.0.0.5", "label": "Office Core Switch"},
    )
    assert res.status_code == 200
    assert res.json()["labels"]["10.0.0.5"] == "Office Core Switch"

    # Verify audit log recorded
    logs = test_env.get_audit_logs(limit=5)
    assert any(log["action"] == "SET_ENDPOINT_LABEL" and "10.0.0.5" in log["resource"] for log in logs)

    # 4. Authenticated DELETE succeeds
    res = client.delete(
        "/api/endpoint-labels/10.0.0.5",
        headers={"X-API-Key": "test-admin-key-2026"},
    )
    assert res.status_code == 200
    assert "10.0.0.5" not in res.json()["labels"]

    # 5. Delete non-existent returns 404
    res = client.delete(
        "/api/endpoint-labels/10.0.0.5",
        headers={"X-API-Key": "test-admin-key-2026"},
    )
    assert res.status_code == 404
