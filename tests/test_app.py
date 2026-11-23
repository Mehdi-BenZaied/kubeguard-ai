from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["project"] == "KubeGuard AI"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_fast_request():
    response = client.get("/work?delay_ms=0")
    assert response.status_code == 200
    assert response.json()["message"] == "OK"


def test_expected_503():
    response = client.get("/work?delay_ms=0&fail=true")
    assert response.status_code == 503


def test_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "kubeguard_requests_total" in response.text
    assert "kubeguard_request_duration_seconds_bucket" in response.text

def test_request_counters_exist_before_first_request():
    import subprocess
    import sys

    code = """
from app.main import app
from prometheus_client import generate_latest

metrics = generate_latest().decode("utf-8")

assert 'kubeguard_requests_total{outcome="success"} 0.0' in metrics
assert 'kubeguard_requests_total{outcome="error"} 0.0' in metrics
"""

    subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )


def test_invalid_delay():
    response = client.get("/work?delay_ms=9000")
    assert response.status_code == 422
