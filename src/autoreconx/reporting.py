from __future__ import annotations

import typer

from autoreconx.models import ScanResult


def print_scan_summary(result: ScanResult) -> None:
    """Print a compact normalized scan summary."""

    typer.echo("")
    typer.echo("[summary] normalized attack surface")
    typer.echo(f" target:       {result.target}")
    typer.echo(f" domains:      {len(result.domains)}")
    typer.echo(f" IP addresses: {len(result.ips)}")
    typer.echo(f" ports:        {len(result.ports)}")
    typer.echo(f" services:     {len(result.services)}")
    typer.echo(f" web apps:     {len(result.web_assets)}")
    typer.echo(f" endpoints:    {len(result.endpoints)}")
