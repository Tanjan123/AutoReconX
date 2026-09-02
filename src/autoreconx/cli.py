import typer

from autoreconx.core.context import create_scan_context
from autoreconx.core.finalize import finalize_scan
from autoreconx.core.pipeline import run_domain_pipeline, run_ip_pipeline
from autoreconx.core.scope import TargetKind, parse_scope
from autoreconx.prioritization import prioritize_scan
from autoreconx.reporting import (
    print_priority_summary,
    print_scan_summary,
)

from . import __version__

app = typer.Typer(
    name="autoreconx",
    help="AutoReconX — authorized reconnaissance & attack-surface mapping framework (V1: skeleton).",
    add_completion=False,
)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Authorized target (domain/IP/CIDR within scope)."),
    ports: bool = typer.Option(False, help="Enable port discovery using naabu (active scan)."),
    allow_public: bool = typer.Option(
        False,
        help="Allow scanning public IPs (DANGEROUS). Enable only if explicitly authorized.",
    ),
    services: bool = typer.Option(False, help="Enable Nmap service enumeration on discovered open ports."),
    web: bool = typer.Option(False, help="Enable HTTP probing using ProjectDiscovery httpx-toolkit."),
    crawl: bool = typer.Option(
        False,
        help="Enable Katana endpoint crawling on discovered web applications.",
    ),
) -> None:

    """
    Pipeline (current):
    scope -> subfinder -> dnsx -> (optional naabu) -> (optional nmap)
    """

    # 1) Scope validation (safety gate)
    try:
        scope = parse_scope(target)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    typer.echo(f"[scope OK] kind={scope.kind} target={scope.target}")

    # Create shared context for this scan
    context = create_scan_context(target, scope)

    # IP / local lab pipeline
    if scope.kind == TargetKind.IP:
        run_ip_pipeline(
            context,
            ports=ports,
            services=services,
            web=web,
            crawl=crawl,
            allow_public=allow_public,
        )
        correlated = finalize_scan(context)
        print_scan_summary(correlated)
        priority_items = prioritize_scan(correlated)
        print_priority_summary(priority_items)
        return

    # Domain reconnaissance pipeline
    if scope.kind == TargetKind.DOMAIN:
        run_domain_pipeline(
            context,
            ports=ports,
            services=services,
            web=web,
            crawl=crawl,
            allow_public=allow_public,
        )
        correlated = finalize_scan(context)
        print_scan_summary(correlated)
        priority_items = prioritize_scan(correlated)
        print_priority_summary(priority_items)
        return

    typer.echo(
        f"[info] target type '{scope.kind}' "
        "is not implemented in the current pipeline."
    )

@app.command()
def version() -> None:
    """Print AutoReconX version."""
    typer.echo(__version__)

def main() -> None:
    app()

if __name__ == "__main__":
    main()

