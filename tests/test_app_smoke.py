"""
Smoke test: the FastAPI app boots, DB tables get created, and the auth flow
(register -> login -> protected route) works end-to-end against a throwaway
sqlite DB. Does NOT touch AWS — that's exercised manually against your real
account via /api/dashboard/scan once credentials are in .env.
"""
import os

os.environ["DATABASE_URL"] = "sqlite:///./test_cloudshield.db"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    if os.path.exists("test_cloudshield.db"):
        os.remove("test_cloudshield.db")

    from app.database import engine
    from app.main import app
    with TestClient(app) as c:
        yield c

    engine.dispose()  # release pooled connections before deleting the file
    if os.path.exists("test_cloudshield.db"):
        os.remove("test_cloudshield.db")


def test_root_endpoint(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "cloudshield"


def test_dashboard_page(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "CloudShield Dashboard" in resp.text


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_login_and_protected_route(client):
    reg = client.post("/api/auth/register", json={"username": "admin", "password": "supersecret123"})
    assert reg.status_code == 200
    token = reg.json()["access_token"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "admin"

    login = client.post("/api/auth/login", data={"username": "admin", "password": "supersecret123"})
    assert login.status_code == 200
    assert "access_token" in login.json()


def test_protected_route_rejects_missing_token(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401
