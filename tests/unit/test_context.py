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
    assert context.result.scan_id == context.scan_id
    assert context.result.target == "example.com"

    assert len(context.result.domains) == 1
    assert context.result.domains[0].hostname == "example.com"
    assert context.result.domains[0].source == "target"
 
def test_create_scan_context_seeds_ip_target(tmp_path: Path):
    scope = parse_scope("127.0.0.1")

    context = create_scan_context(
        "127.0.0.1",
        scope,
        workspace_root=tmp_path,
    )

    assert len(context.result.ips) == 1
    assert context.result.ips[0].address == "127.0.0.1"
    assert context.result.ips[0].source == "target"
