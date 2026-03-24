from __future__ import annotations

from collections.abc import Generator
from os import getenv

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import create_db_engine, create_session_factory


def _default_database_url() -> str:
    return getenv("DATABASE_URL", "sqlite+pysqlite:///./repo_secret_auditor.db")


ENGINE: Engine = create_db_engine(_default_database_url())
SESSION_FACTORY: sessionmaker[Session] = create_session_factory(ENGINE)


def get_db_session() -> Generator[Session, None, None]:
    session = SESSION_FACTORY()
    try:
        yield session
    finally:
        session.close()
