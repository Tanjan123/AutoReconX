from __future__ import annotations

import typer

from autoreconx.core.context import ScanContext
from autoreconx.correlation import (
    CorrelatedScanResult,
    correlate_scan,
)
from autoreconx.storage import save_correlated_scan


def finalize_scan(
    context: ScanContext,
) -> CorrelatedScanResult:
    """
    Correlate the completed scan and persist it to SQLite.
    """

    correlated = correlate_scan(context.result)

    save_correlated_scan(
        correlated,
        context.database_path,
    )

    typer.echo(f"[saved] database: {context.database_path}")

    return correlated
