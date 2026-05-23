"""Database session manager."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from configs.settings import get_settings
from database.models import Base
from utils.logger import get_logger

log = get_logger(__name__)

_engine = None
_SessionLocal = None


def init_db() -> None:
    """Create tables if they don't exist."""
    global _engine, _SessionLocal
    url = get_settings().get("database.url", "sqlite:///data/vulnpilot.db")

    if url.startswith("sqlite:///"):
        Path(url.replace("sqlite:///", "")).parent.mkdir(parents=True, exist_ok=True)

    _engine = create_engine(url, echo=False, future=True)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(_engine)
    log.info("Database initialized at %s", url)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""
    if _SessionLocal is None:
        init_db()
    session: Session = _SessionLocal()  # type: ignore[misc]
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
