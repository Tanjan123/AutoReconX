from pathlib import Path

from autoreconx.core.context import (
    create_scan_context,
)
from autoreconx.core.finalize import finalize_scan
from autoreconx.core.scope import parse_scope


def test_finalize_scan_creates_database(
    tmp_path: Path,
):
    scope = parse_scope("127.0.0.1")

    context = create_scan_context(
        "127.0.0.1",
        scope,
        workspace_root=tmp_path,
    )

    correlated = finalize_scan(context)

    assert context.database_path.exists()
    assert correlated.target == "127.0.0.1"
    assert len(correlated.ips) == 1
