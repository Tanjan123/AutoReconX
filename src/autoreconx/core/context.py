from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from autoreconx.core.runner import CommandRunner
from autoreconx.core.scope import Scope, TargetKind
from autoreconx.models import DomainAsset, IPAsset, ScanResult


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
    result: ScanResult
    database_path: Path
    report_dir: Path

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

    scan_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    workspace = workspace_root / scan_id
    raw_dir = workspace / "raw"
    database_path = workspace / "autoreconx.db"
    report_dir = workspace / "reports"

    raw_dir.mkdir(parents=True, exist_ok=True)

    runner = CommandRunner(default_timeout=default_timeout)
   
    result = ScanResult(
        scan_id=scan_id,
        target=scope.target,
    )

    # Seed the explicitly supplied target into normalized results.
    if scope.kind == TargetKind.DOMAIN:
        result.domains.append(
            DomainAsset(
                hostname=scope.target,
                source="target",
            )
        )

    elif scope.kind == TargetKind.IP:
        result.ips.append(
            IPAsset(
                address=scope.target,
                source="target",
            )
        )

    return ScanContext(
        scan_id=scan_id,
        original_target=original_target,
        scope=scope,
        workspace=workspace,
        database_path=database_path,
        raw_dir=raw_dir,
        runner=runner,
        report_dir=report_dir,
        result=result,
    )

