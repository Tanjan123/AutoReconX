from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from autoreconx.core.runner import CommandRunner
from autoreconx.core.scope import Scope


@dataclass
class ScanContext:
    """
    Shared state for one AutoReconX scan.

    The context gives pipeline stages access to the same target,
    scope, workspace and command runner.
    """

    scan_id: str
    original_target: str
    scope: Scope
    workspace: Path
    raw_dir: Path
    runner: CommandRunner


def create_scan_context(
    original_target: str,
    scope: Scope,
    *,
    workspace_root: Path = Path("workspaces"),
    default_timeout: int = 120,
) -> ScanContext:
    """
    Create the workspace and shared execution context for one scan.
    """

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    workspace = workspace_root / scan_id
    raw_dir = workspace / "raw"

    raw_dir.mkdir(parents=True, exist_ok=True)

    runner = CommandRunner(default_timeout=default_timeout)

    return ScanContext(
        scan_id=scan_id,
        original_target=original_target,
        scope=scope,
        workspace=workspace,
        raw_dir=raw_dir,
        runner=runner,
    )
