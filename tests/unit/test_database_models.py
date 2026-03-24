import json

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Scan
from app.repositories.scan_repository import ScanRepository


def test_metadata_contains_expected_tables() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)

        table_names = set(inspect(engine).get_table_names())

        assert table_names == {"scan", "finding", "vulnerability", "scan_summary"}
    finally:
        engine.dispose()


def test_scan_repository_can_create_and_read_scan() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            repo = ScanRepository(session)
            created = repo.create_scan("https://github.com/h3n-x/repo-secret-auditor", "abc123")
            session.commit()

            persisted = repo.get_by_id(created.id)

            assert persisted is not None
            assert isinstance(persisted, Scan)
            assert persisted.repo_url == "https://github.com/h3n-x/repo-secret-auditor"
            assert persisted.commit_sha == "abc123"
            assert persisted.status == "queued"
    finally:
        engine.dispose()


def test_scan_repository_can_upsert_scan_summary_and_risk_score() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            repo = ScanRepository(session)
            created = repo.create_scan("https://github.com/h3n-x/repo-secret-auditor", "abc123")

            repo.upsert_scan_summary(
                created.id,
                total_findings=4,
                critical_count=1,
                high_count=1,
                medium_count=1,
                low_count=1,
                risk_score=72.5,
            )
            session.commit()

            persisted = repo.get_by_id(created.id)
            assert persisted is not None
            assert persisted.summary is not None
            assert persisted.summary.total_findings == 4
            assert persisted.summary.critical_count == 1

            metadata = json.loads(persisted.metadata_json or "{}")
            assert metadata["risk_score"] == 72.5

            repo.upsert_scan_summary(
                created.id,
                total_findings=2,
                critical_count=0,
                high_count=1,
                medium_count=1,
                low_count=0,
                risk_score=41.0,
            )
            session.commit()

            updated = repo.get_by_id(created.id)
            assert updated is not None
            assert updated.summary is not None
            assert updated.summary.total_findings == 2
            assert updated.summary.critical_count == 0

            updated_metadata = json.loads(updated.metadata_json or "{}")
            assert updated_metadata["risk_score"] == 41.0
    finally:
        engine.dispose()
