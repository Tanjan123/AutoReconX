from __future__ import annotations

import typer

from autoreconx.correlation import (
    CorrelatedScanResult,
)
from autoreconx.prioritization import PriorityItem


def print_scan_summary(
    result: CorrelatedScanResult,
) -> None:
    """Print a compact correlated attack-surface summary."""

    typer.echo("")
    typer.echo(
        "[summary] correlated attack surface"
    )

    typer.echo(
        f" target:       {result.target}"
    )

    typer.echo(
        f" domains:      {len(result.domains)}"
    )

    typer.echo(
        f" IP addresses: {len(result.ips)}"
    )

    typer.echo(
        f" ports:        {len(result.ports)}"
    )

    typer.echo(
        f" services:     {len(result.services)}"
    )

    typer.echo(
        f" web apps:     {len(result.web_assets)}"
    )

    typer.echo(
        f" endpoints:    {len(result.endpoints)}"
    )

    typer.echo(
        f" relationships: "
        f"{len(result.relationships)}"
    )

def print_priority_summary(
    items: tuple[PriorityItem, ...],
    *,
    limit: int = 10,
) -> None:
    """
    Print the highest-priority assets for manual investigation.

    Priority indicates reconnaissance interest, not confirmed vulnerability.
    """

    typer.echo("")
    typer.echo("[priority] top investigation candidates")

    if not items:
        typer.echo(" no priority indicators identified")
        return

    for item in items[:limit]:
        typer.echo(
            f" {item.level.value.upper():6} "
            f"{item.score:>3} "
            f"{item.asset_type:8} "
            f"{item.asset_id}"
        )

        for reason in item.reasons:
            typer.echo(
                f"          - {reason}"
            )
