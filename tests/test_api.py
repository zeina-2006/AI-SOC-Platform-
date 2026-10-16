from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_home_endpoint():
    response = client.get("/")
    assert response.status_code == 200


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200


def test_events_endpoint():
    response = client.get("/events")
    assert response.status_code == 200


def test_alerts_endpoint():
    response = client.get("/alerts")
    assert response.status_code == 200