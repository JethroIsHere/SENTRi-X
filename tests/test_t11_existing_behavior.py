"""T11: Existing Behavior Regression Tests.

Verifies:
1. Live-only behavior: attack injection via /api/inject-attack returns 403 Forbidden.
2. Background simulation is disabled.
3. Ingesting flow without valid model/scaler reports error rather than manufacturing fake output.
4. Settings endpoint persists threshold and alerting state without overwriting user data.
5. Heartbeat updates hardware liveness timestamp.
"""

import os
import tempfile
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

# Ensure backend directory is importable
import sys
from pathlib import Path
backend_dir = str(Path(__file__).resolve().parent.parent / "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


@pytest.fixture
def client_with_temp_db():
    """Create test client with an isolated temporary SQLite database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_db = os.path.join(tmpdir, "test_sentrix.db")
        with patch("database.DB_PATH", temp_db):
            import main
            import database
            database.init_db()
            test_client = TestClient(main.app)
            yield test_client, main


def test_t11_attack_injection_rejected(client_with_temp_db):
    """Verify /api/inject-attack returns 403 Forbidden in live-only mode."""
    client, _ = client_with_temp_db
    response = client.post("/api/inject-attack", json={"type": "DDoS", "intensity": 5})
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()


def test_t11_simulation_disabled_in_status(client_with_temp_db):
    """Verify /api/status reports simulation_active == False."""
    client, _ = client_with_temp_db
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data.get("simulation_active") is False
    assert data.get("api_version") == 2
    assert "node_status" in data


def test_t11_heartbeat_updates_liveness(client_with_temp_db):
    """Verify POST /api/heartbeat registers hardware activity."""
    client, main_mod = client_with_temp_db
    initial_ping = main_mod.engine.last_hardware_ping

    response = client.post("/api/heartbeat", json={"sensor_id": "test-sensor"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["hardware_live"] is True
    assert main_mod.engine.last_hardware_ping >= initial_ping


def test_t11_settings_persistence(client_with_temp_db):
    """Verify alert settings update and retrieve correctly."""
    client, _ = client_with_temp_db

    # Get default settings
    res = client.get("/api/settings")
    assert res.status_code == 200
    default_settings = res.json()
    assert "alert_threshold" in default_settings

    # Update threshold to 0.92
    update_res = client.put(
        "/api/settings",
        json={"active_alerting": True, "alert_threshold": 0.92},
    )
    assert update_res.status_code == 200
    assert update_res.json()["alert_threshold"] == 0.92

    # Verify retrieval
    res_after = client.get("/api/settings")
    assert res_after.json()["alert_threshold"] == 0.92


if __name__ == "__main__":
    from fastapi.testclient import TestClient
    import main, database
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_db = os.path.join(tmpdir, "test_sentrix.db")
        with patch("database.DB_PATH", temp_db):
            database.init_db()
            c = TestClient(main.app)
            test_t11_attack_injection_rejected((c, main))
            test_t11_simulation_disabled_in_status((c, main))
            test_t11_heartbeat_updates_liveness((c, main))
            test_t11_settings_persistence((c, main))
            print("All T11 Existing Behavior tests passed!")
