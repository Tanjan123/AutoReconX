from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Base class for AutoReconX SQLite tables."""


def create_database_engine(
    database_path: Path,
) -> Engine:
    """Create a local SQLite database engine."""

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return create_engine(
        f"sqlite:///{database_path}",
        future=True,
    )


def create_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    """Create SQLAlchemy sessions for AutoReconX."""

    return sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )


def initialize_database(
    engine: Engine,
) -> None:
    """Create AutoReconX database tables."""
    from autoreconx.storage import tables  # noqa: F401

    Base.metadata.create_all(engine)
