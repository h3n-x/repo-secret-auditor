from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


def test_openapi_smoke() -> None:
    with TestClient(app) as client:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        body = response.json()
        assert "paths" in body
        assert "/scans" in body["paths"]


def test_create_scan_invalid_payload_smoke() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/scans",
            json={
                "repo_url": "not-a-valid-url",
                "ref": "main",
            },
        )

        assert response.status_code == 422
