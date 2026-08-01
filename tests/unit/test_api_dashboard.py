import pytest
from fastapi.testclient import TestClient
from contract_audit.api.app import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    # TestClient internally handles SessionMiddleware context
    return TestClient(app)


def test_health_check(client):
    """Verify that the health check endpoint remains functional."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "1.0.0"}


def test_dashboard_endpoint_serves_html(client):
    """Verify the root endpoint serves our Single Page Application HTML."""
    response = client.get("/")
    assert response.status_code == 200
    # Check that it returns HTML containing contract-audit or app entry points
    assert "text/html" in response.headers["content-type"]
    assert "contract-audit" in response.text or "Contract Audit" in response.text


def test_static_css_and_js_served(client):
    """Verify that mounted static files are reachable."""
    # Serve index.html first to guarantee the static directory and files are initialized
    client.get("/")
    
    css_res = client.get("/static/css/style.css")
    assert css_res.status_code == 200
    assert "text/css" in css_res.headers["content-type"]

    js_res = client.get("/static/js/app.js")
    assert js_res.status_code == 200
    assert "javascript" in js_res.headers["content-type"]


def test_developer_login_flow(client):
    """Verify that the developer mock authentication flow injects the session."""
    # Initially we should be unauthenticated when checking /auth/me
    me_res = client.get("/auth/me")
    assert me_res.status_code == 401

    # Trigger developer bypass login
    # follow_redirects=False to verify the redirect target and session injection
    login_res = client.get("/auth/dev-login", follow_redirects=False)
    assert login_res.status_code == 307
    assert login_res.headers["location"] == "/"

    # Check /auth/me again (using the same client with persisted cookies/session)
    me_authenticated_res = client.get("/auth/me")
    assert me_authenticated_res.status_code == 200
    user_info = me_authenticated_res.json()
    assert user_info["email"] == "dev@contractaudit.local"
    assert user_info["name"] == "Dev User"
