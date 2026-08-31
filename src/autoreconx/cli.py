import typer
from . import __version__
from autoreconx.core.scope import parse_scope

app = typer.Typer(
    name="autoreconx",
    help="AutoReconX — authorized reconnaissance & attack-surface mapping framework (V1: skeleton).",
    add_completion=False,
)

@app.command()
def scan(target: str = typer.Argument(..., help="Authorized target (domain/IP/CIDR within scope).")) -> None:
    """
    V1: validates target/scope first. Recon execution will be added next.
    """
    try:
        scope = parse_scope(target)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    typer.echo(f"[scope OK] kind={scope.kind} target={scope.target}")
    typer.echo("Next: implement command runner + first recon module (subfinder).")

@app.command()
def version() -> None:
    """Print AutoReconX version."""
    typer.echo(__version__)

def main() -> None:
    app()

if __name__ == "__main__":
    main()
