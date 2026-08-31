import typer
from . import __version__

app = typer.Typer(
    name="autoreconx",
    help="AutoReconX — authorized reconnaissance & attack-surface mapping framework (V1: skeleton).",
    add_completion=False,
)

@app.command()
def version() -> None:
    """Print AutoReconX version."""
    typer.echo(__version__)

@app.command()
def scan(target: str = typer.Argument(..., help="Authorized target (domain/IP/CIDR within scope).")) -> None:
    """
    Placeholder scan command (implementation comes next).
    """
    typer.echo(f"[V1 skeleton] target={target}")
    typer.echo("Next: scope validation + command runner + first recon module (subfinder).")

def main() -> None:
    app()

if __name__ == "__main__":
    main()
