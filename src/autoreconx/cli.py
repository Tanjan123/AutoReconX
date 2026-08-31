import typer
from . import __version__
from autoreconx.core.scope import parse_scope
from pathlib import Path
from datetime import datetime

from autoreconx.core.runner import CommandRunner
from autoreconx.modules.subfinder import build_subfinder_args, parse_subfinder_stdout
from autoreconx.core.scope import TargetKind

app = typer.Typer(
    name="autoreconx",
    help="AutoReconX — authorized reconnaissance & attack-surface mapping framework (V1: skeleton).",
    add_completion=False,
)

@app.command()
def scan(target: str = typer.Argument(..., help="Authorized target (domain/IP/CIDR within scope).")) -> None:
    """
    V1: validates target/scope first. Recon execution will be added next.
    Currently implemented: Subfinder (domain scope only).
    """
    # 1) Scope validation (safety gate)
    try:
        scope = parse_scope(target)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    typer.echo(f"[scope OK] kind={scope.kind} target={scope.target}")

    # 2) V1: run subfinder only for domain targets
    if scope.kind != TargetKind.DOMAIN:
        typer.echo("[info] Subfinder runs only for domain targets in V1.")
        return

    # 3) Create a simple workspace for this scan (raw evidence)
    scan_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    workspace = Path("workspaces") / scan_id
    raw_dir = workspace / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 4) Run subfinder via the centralized runner
    runner = CommandRunner(default_timeout=120)
    args = build_subfinder_args(scope.target)

    typer.echo("[run] subfinder (passive subdomain discovery)")
    result = runner.run(
        args,
        stdout_path=str(raw_dir / "subfinder.txt"),
        stderr_path=str(raw_dir / "subfinder.err"),
    )

    # 5) Handle failure states safely
    if result.timed_out:
        typer.echo("[warn] subfinder timed out")
        typer.echo(f"[saved] stderr: {raw_dir / 'subfinder.err'}")
        return

    if result.returncode != 0:
        typer.echo(f"[warn] subfinder failed (rc={result.returncode})")
        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])
        typer.echo(f"[saved] stderr: {raw_dir / 'subfinder.err'}")
        return

    # 6) Parse + show summary
    parsed = parse_subfinder_stdout(result.stdout, root_domain=scope.target)

    typer.echo(f"[ok] subdomains discovered: {len(parsed.subdomains)}")
    for s in parsed.subdomains[:10]:
        typer.echo(f" - {s}")

    typer.echo(f"[saved] raw output: {raw_dir / 'subfinder.txt'}")

@app.command()
def version() -> None:
    """Print AutoReconX version."""
    typer.echo(__version__)

def main() -> None:
    app()

if __name__ == "__main__":
    main()
