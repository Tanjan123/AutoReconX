from __future__ import annotations

import typer

from autoreconx.correlation import correlate_scan
from autoreconx.models import ScanResult


def print_scan_summary(result: ScanResult) -> None:
    correlated = correlate_scan(result)

    """Print a compact normalized scan summary."""

    typer.echo("")
    typer.echo("[summary] correlated attack surface")
    typer.echo(f" target:       {correlated.target}")
    typer.echo(f" domains:      {len(correlated.domains)}")
    typer.echo(f" IP addresses: {len(correlated.ips)}")
    typer.echo(f" ports:        {len(correlated.ports)}")
    typer.echo(f" services:     {len(correlated.services)}")
    typer.echo(f" web apps:     {len(correlated.web_assets)}")
    typer.echo(f" endpoints:    {len(correlated.endpoints)}")
