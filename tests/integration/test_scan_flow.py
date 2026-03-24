from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.db.base import Base
from app.db.dependencies import ENGINE, SESSION_FACTORY
from app.db.models import Finding, Scan, ScanSummary, Vulnerability
from app.main import app


def _reset_database() -> None:
    Base.metadata.create_all(bind=ENGINE)
    with SESSION_FACTORY() as session:
        session.execute(delete(Vulnerability))
        session.execute(delete(Finding))
        session.execute(delete(ScanSummary))
        session.execute(delete(Scan))
        session.commit()


@pytest.fixture(autouse=True)
def clean_database() -> Generator[None, None, None]:
    _reset_database()
    yield
    _reset_database()


def test_create_and_get_scan_flow() -> None:
    payload = {
        "repo_url": "https://github.com/user/repo.git",
        "ref": "main",
    }

    with TestClient(app) as client:
        create_response = client.post("/scans", json=payload)
        assert create_response.status_code == 202

        created = create_response.json()
        assert created["status"] == "queued"
        assert created["scan_id"] > 0

        scan_id = created["scan_id"]
        detail_response = client.get(f"/scans/{scan_id}")
        assert detail_response.status_code == 200

        detail = detail_response.json()
        assert detail["scan_id"] == scan_id
        assert detail["repo_url"] == payload["repo_url"]
        assert detail["commit_sha"] == payload["ref"]
        assert detail["total_findings"] == 0


def test_get_findings_empty_result_with_pagination() -> None:
    payload = {
        "repo_url": "https://github.com/user/repo.git",
        "ref": "main",
    }

    with TestClient(app) as client:
        create_response = client.post("/scans", json=payload)
        assert create_response.status_code == 202

        scan_id = create_response.json()["scan_id"]
        findings_response = client.get(
            f"/scans/{scan_id}/findings",
            params={"limit": 10, "offset": 0},
        )

        assert findings_response.status_code == 200
        findings = findings_response.json()
        assert findings["scan_id"] == scan_id
        assert findings["total"] == 0
        assert findings["items"] == []
        assert findings["limit"] == 10
        assert findings["offset"] == 0
