from __future__ import annotations

from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.dependencies import get_db_session
from app.db.models import Finding, FindingType, Severity
from app.main import app

ENGINE = create_engine(
    "sqlite+pysqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(ENGINE)


def _session_override() -> Generator[Session, None, None]:
    session = Session(ENGINE)
    try:
        yield session
    finally:
        session.close()


def _client() -> TestClient:
    app.dependency_overrides[get_db_session] = _session_override
    return TestClient(app)


def _insert_finding(
    *,
    scan_id: int,
    finding_type: str,
    severity: str,
    rule_id: str,
    file_path: str,
    line_start: int,
) -> None:
    with Session(ENGINE) as session:
        session.add(
            Finding(
                scan_id=scan_id,
                type=finding_type,
                rule_id=rule_id,
                file_path=file_path,
                line_start=line_start,
                line_end=line_start,
                evidence_hash=f"hash-{scan_id}-{rule_id}-{line_start}",
                severity=severity,
                confidence=0.9,
                recommendation="Rotate credential",
            )
        )
        session.commit()


def test_create_scan_returns_queued() -> None:
    with _client() as client:
        response = client.post(
            "/scans",
            json={"repo_url": "https://github.com/h3n-x/repo-secret-auditor", "ref": "main"},
        )

    assert response.status_code == 202
    body = response.json()
    assert body["scan_id"] > 0
    assert body["status"] == "queued"
    assert body["job_id"].startswith("scan-")


def test_get_scan_returns_404_when_not_found() -> None:
    with _client() as client:
        response = client.get("/scans/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_get_scan_returns_created_scan() -> None:
    with _client() as client:
        create_response = client.post(
            "/scans",
            json={"repo_url": "https://github.com/h3n-x/repo-secret-auditor", "ref": "dev"},
        )
        scan_id = create_response.json()["scan_id"]

        get_response = client.get(f"/scans/{scan_id}")

    assert get_response.status_code == 200
    body = get_response.json()
    assert body["scan_id"] == scan_id
    assert body["repo_url"] == "https://github.com/h3n-x/repo-secret-auditor"
    assert body["commit_sha"] == "dev"
    assert body["status"] == "queued"


def test_get_scan_findings_returns_paginated_results() -> None:
    with _client() as client:
        create_response = client.post(
            "/scans",
            json={"repo_url": "https://github.com/h3n-x/repo-secret-auditor", "ref": "day7"},
        )
        scan_id = create_response.json()["scan_id"]

        _insert_finding(
            scan_id=scan_id,
            finding_type=FindingType.SECRET.value,
            severity=Severity.HIGH.value,
            rule_id="secret.github_pat",
            file_path="src/a.py",
            line_start=10,
        )
        _insert_finding(
            scan_id=scan_id,
            finding_type=FindingType.DEPENDENCY.value,
            severity=Severity.MEDIUM.value,
            rule_id="dep.osv",
            file_path="requirements.txt",
            line_start=1,
        )
        _insert_finding(
            scan_id=scan_id,
            finding_type=FindingType.SECRET.value,
            severity=Severity.LOW.value,
            rule_id="secret.generic_api_key",
            file_path="src/b.py",
            line_start=22,
        )

        response = client.get(f"/scans/{scan_id}/findings?limit=2&offset=1")

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "v1"
    assert body["scan_id"] == scan_id
    assert body["total"] == 3
    assert body["limit"] == 2
    assert body["offset"] == 1
    assert len(body["items"]) == 2
    assert body["items"][0]["rule_id"] == "dep.osv"
    assert body["items"][1]["rule_id"] == "secret.generic_api_key"


def test_get_scan_findings_supports_filters() -> None:
    with _client() as client:
        create_response = client.post(
            "/scans",
            json={"repo_url": "https://github.com/h3n-x/repo-secret-auditor", "ref": "filters"},
        )
        scan_id = create_response.json()["scan_id"]

        _insert_finding(
            scan_id=scan_id,
            finding_type=FindingType.SECRET.value,
            severity=Severity.HIGH.value,
            rule_id="secret.github_pat",
            file_path="src/high.py",
            line_start=3,
        )
        _insert_finding(
            scan_id=scan_id,
            finding_type=FindingType.DEPENDENCY.value,
            severity=Severity.HIGH.value,
            rule_id="dep.critical",
            file_path="package-lock.json",
            line_start=1,
        )
        _insert_finding(
            scan_id=scan_id,
            finding_type=FindingType.SECRET.value,
            severity=Severity.MEDIUM.value,
            rule_id="secret.generic_api_key",
            file_path="src/medium.py",
            line_start=7,
        )

        response = client.get(f"/scans/{scan_id}/findings?severity=high&type=secret")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["rule_id"] == "secret.github_pat"


def test_get_scan_findings_returns_404_for_unknown_scan() -> None:
    with _client() as client:
        response = client.get("/scans/999/findings")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_get_scan_findings_returns_422_for_invalid_filters() -> None:
    with _client() as client:
        create_response = client.post(
            "/scans",
            json={"repo_url": "https://github.com/h3n-x/repo-secret-auditor", "ref": "invalid"},
        )
        scan_id = create_response.json()["scan_id"]

        bad_severity = client.get(f"/scans/{scan_id}/findings?severity=severe")
        bad_type = client.get(f"/scans/{scan_id}/findings?type=config")

    assert bad_severity.status_code == 422
    assert bad_severity.json()["detail"] == "Invalid severity filter"
    assert bad_type.status_code == 422
    assert bad_type.json()["detail"] == "Invalid type filter"
