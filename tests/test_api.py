"""
Tests for the VigilantNet Backend API.

These tests focus on the core security logic and API boundaries:
1. Risk Engine: Verifies classification logic (e.g. Telnet is Critical).
2. Auth Layer: Verifies that missing/bad API keys are rejected.
3. Target Allow-List: Verifies that attempting to scan public IPs is blocked.
"""

from fastapi.testclient import TestClient

from app.main import app
from app.services.risk_engine import classify_port

client = TestClient(app)

# ---------------------------------------------------------------------------
# Test Risk Engine
# ---------------------------------------------------------------------------
def test_risk_engine_critical():
    """Verify Telnet is flagged as Critical."""
    result = classify_port(23, "telnet")
    assert result["risk_level"] == "Critical"
    assert "plaintext" in result["description"].lower()


def test_risk_engine_unknown_port():
    """Verify unknown ports fall back to 'Info' level."""
    result = classify_port(9999, "custom")
    assert result["risk_level"] == "Info"
    assert "no specific risk rule" in result["description"].lower()


# ---------------------------------------------------------------------------
# Test Auth & Access Control
# ---------------------------------------------------------------------------
def test_scan_no_api_key():
    """Verify scanning fails without an API key."""
    response = client.post("/api/v1/scan", json={"target": "127.0.0.1"})
    assert response.status_code == 422  # Unprocessable Entity (missing header)


def test_scan_bad_api_key():
    """Verify scanning fails with a wrong API key."""
    response = client.post(
        "/api/v1/scan",
        json={"target": "127.0.0.1"},
        headers={"X-API-Key": "wrong-key"}
    )
    assert response.status_code == 401


def test_scan_disallowed_target():
    """
    Verify scanning a public internet IP is blocked by the allow-list.
    This tests the 'Responsible Scope' requirement.
    """
    # 8.8.8.8 is a public Google DNS server. Our scanner should refuse it.
    response = client.post(
        "/api/v1/scan",
        json={"target": "8.8.8.8"},
        headers={"X-API-Key": "changeme"}
    )
    assert response.status_code == 403
    assert "restricted to local/owned networks only" in response.json()["detail"]


def test_discover_public_subnet():
    """Verify discovering a public subnet is blocked."""
    response = client.post(
        "/api/v1/discover",
        json={"subnet": "8.8.8.0/24"},
        headers={"X-API-Key": "changeme"}
    )
    assert response.status_code == 403
    assert "not a private network range" in response.json()["detail"]
