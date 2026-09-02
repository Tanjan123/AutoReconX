from pathlib import Path

from sqlalchemy import inspect

from autoreconx.storage import (
    create_database_engine,
    initialize_database,
)


def test_initialize_database_creates_tables(
    tmp_path: Path,
):
    db_path = tmp_path / "autoreconx.db"

    engine = create_database_engine(db_path)

    initialize_database(engine)

    inspector = inspect(engine)

    tables = set(inspector.get_table_names())

    assert "scans" in tables
    assert "assets" in tables
    assert "relationships" in tables

    assert db_path.exists()
