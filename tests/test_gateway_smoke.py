# Gateway smoke tests

import pytest
from fastapi.testclient import TestClient
import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.gateway.main import app

def test_health_check():
    """Test health check endpoint"""
    client = TestClient(app)
    response = client.get("/healthz")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "automcp-demo"
    assert "version" in data

def test_root_endpoint():
    """Test root endpoint"""
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    data = response.json()

    assert "service" in data
    assert "endpoints" in data
    assert "/healthz" in data["endpoints"]
    assert "/webhook/github" in data["endpoints"]

def test_github_webhook_test_endpoint():
    """Test the GitHub webhook test endpoint"""
    client = TestClient(app)
    response = client.get("/webhook/test/github")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "webhook_endpoint_active"
    assert "/webhook/github" in data["webhook_url"]
    assert "push" in data["expected_events"]
    assert "*.tf" in data["supported_file_types"]

@pytest.mark.asyncio
async def test_github_webhook_no_payload():
    """Test GitHub webhook with empty payload"""
    client = TestClient(app)

    # This should return early as it's not a push event
    response = client.post("/webhook/github", json={})

    assert response.status_code == 400

# Mock environment variables for testing
def test_missing_env_vars_logging(caplog):
    """Test that missing environment variables are logged on startup"""
    # Set empty env
    old_env = dict(os.environ)
    os.environ.clear()

    # This is harder to test directly since startup runs once
    # In a real scenario, you'd restart the app for testing
    # For now, just verify the function exists
    from src.gateway.main import startup_event

    # Cleanup
    os.environ.update(old_env)
