from backend.detection_history import DetectionHistoryStore
from fastapi.testclient import TestClient
from backend.main import app


def test_sqlite_history_survives_restart_and_enforces_bound(tmp_path):
    path = tmp_path / "detections.sqlite3"
    first = DetectionHistoryStore(path, limit=2)
    first.append({"prediction": "Benign", "replay_session_id": "keep"})
    first.append({"prediction": "Attack", "replay_session_id": "remove"})
    first.append({"prediction": "Attack", "replay_session_id": "keep"})

    restarted = DetectionHistoryStore(path, limit=2)
    assert [record["id"] for record in restarted.latest()] == [3, 2]
    assert len(restarted.latest()) == 2

    restarted.remove_replay("remove")
    assert [record["id"] for record in restarted.latest()] == [3]


def test_env_api_key_guards_non_health_routes(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEY", "test-secret")
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/dashboard").status_code == 401
        assert client.get("/api/dashboard", headers={"X-API-Key": "test-secret"}).status_code == 200
