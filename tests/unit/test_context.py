from pathlib import Path

from autoreconx.core.context import create_scan_context
from autoreconx.core.scope import parse_scope


def test_create_scan_context(tmp_path: Path):
    scope = parse_scope("example.com")

    context = create_scan_context(
        "example.com",
        scope,
        workspace_root=tmp_path,
    )

    assert context.scope.target == "example.com"
    assert context.original_target == "example.com"

    assert context.workspace.exists()
    assert context.raw_dir.exists()

    assert context.raw_dir == context.workspace / "raw"

    assert context.scan_id
    assert context.runner is not None
