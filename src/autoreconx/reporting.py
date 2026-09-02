from __future__ import annotations

import typer

from autoreconx.correlation import (
    CorrelatedScanResult,
)


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
