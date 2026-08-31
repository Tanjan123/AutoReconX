import typer
from . import __version__
from autoreconx.core.scope import parse_scope
from pathlib import Path
from datetime import datetime

from autoreconx.core.runner import CommandRunner
from autoreconx.modules.subfinder import build_subfinder_args, parse_subfinder_stdout
from autoreconx.core.scope import TargetKind
from autoreconx.modules.dnsx import build_dnsx_args, parse_dnsx_output, write_lines
from autoreconx.modules.naabu import build_naabu_args, filter_ips, parse_naabu_output

app = typer.Typer(
    name="autoreconx",
    help="AutoReconX — authorized reconnaissance & attack-surface mapping framework (V1: skeleton).",
    add_completion=False,
)

@app.command()
def scan(target: str = typer.Argument(..., help="Authorized target (domain/IP/CIDR within scope)."),
ports: bool = typer.Option(False, help="Enable port discovery using naabu (active scan)."),
    allow_public: bool = typer.Option(
        False,
        help="Allow scanning public IPs (DANGEROUS). Enable only if explicitly authorized.",
    ),) -> None:

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

    # 7) dnsx stage (DNS resolution)
    typer.echo("[run] dnsx (DNS resolution)")

    # write subdomains to file for dnsx input
    subdomains_file = raw_dir / "subdomains.txt"
    write_lines(str(subdomains_file), parsed.subdomains)

    dnsx_args = build_dnsx_args(str(subdomains_file))

    try:
        dnsx_res = runner.run(
            dnsx_args,
            timeout=600,  # dns resolution can take longer; keep a hard cap
            stdout_path=str(raw_dir / "dnsx.jsonl"),
            stderr_path=str(raw_dir / "dnsx.err"),
        )
    except FileNotFoundError as e:
        typer.echo(f"[warn] {e}")
        typer.echo("[hint] install dnsx and ensure it is in PATH")
        return

    if dnsx_res.timed_out:
        typer.echo("[warn] dnsx timed out")
        typer.echo(f"[saved] raw dnsx stderr: {raw_dir / 'dnsx.err'}")
        return

    if dnsx_res.returncode != 0:
        typer.echo(f"[warn] dnsx failed (rc={dnsx_res.returncode})")
        if dnsx_res.stderr.strip():
            typer.echo(dnsx_res.stderr.strip()[:500])
        typer.echo(f"[saved] raw dnsx stderr: {raw_dir / 'dnsx.err'}")
        return

    resolved = parse_dnsx_output(dnsx_res.stdout, root_domain=scope.target)
    typer.echo(f"[ok] resolved hosts: {len(resolved.resolved)}")
    for item in resolved.resolved[:10]:
        typer.echo(f" - {item.host} -> {', '.join(item.ips)}")

    typer.echo(f"[saved] dnsx raw output: {raw_dir / 'dnsx.jsonl'}")

    # 8) naabu stage (port discovery) - optional
    if not ports:
        typer.echo("[info] port discovery disabled (use --ports to enable naabu stage).")
        return

    # Collect IPs from dnsx resolved results
    all_ips: list[str] = []
    for hr in resolved.resolved:
        all_ips.extend(list(hr.ips))

    # Safety: default is private IPs only unless allow_public=True
    scan_ips = filter_ips(all_ips, allow_public=allow_public)

    if not scan_ips:
        typer.echo("[warn] no IPs eligible for scanning (private-only by default).")
        typer.echo("[hint] use --allow-public only if you are explicitly authorized to scan those public IPs.")
        return

    typer.echo(f"[run] naabu (port discovery) targets={len(scan_ips)} allow_public={allow_public}")

    ips_file = raw_dir / "ips.txt"
    write_lines(str(ips_file), scan_ips)

    naabu_args = build_naabu_args(str(ips_file), top_ports=100, rate=200)

    try:
        naabu_res = runner.run(
            naabu_args,
            timeout=600,
            stdout_path=str(raw_dir / "naabu.jsonl"),
            stderr_path=str(raw_dir / "naabu.err"),
        )
    except FileNotFoundError as e:
        typer.echo(f"[warn] {e}")
        typer.echo("[hint] install naabu and ensure it is in PATH")
        return

    if naabu_res.timed_out:
        typer.echo("[warn] naabu timed out")
        typer.echo(f"[saved] raw naabu stderr: {raw_dir / 'naabu.err'}")
        return

    if naabu_res.returncode != 0:
        typer.echo(f"[warn] naabu failed (rc={naabu_res.returncode})")
        if naabu_res.stderr.strip():
            typer.echo(naabu_res.stderr.strip()[:500])
        typer.echo(f"[saved] raw naabu stderr: {raw_dir / 'naabu.err'}")
        return

    open_ports = parse_naabu_output(naabu_res.stdout)
    typer.echo(f"[ok] open ports found: {len(open_ports.open_ports)}")
    for p in open_ports.open_ports[:10]:
        typer.echo(f" - {p.ip}:{p.port}")

    typer.echo(f"[saved] naabu raw output: {raw_dir / 'naabu.jsonl'}")



@app.command()
def version() -> None:
    """Print AutoReconX version."""
    typer.echo(__version__)

def main() -> None:
    app()

if __name__ == "__main__":
    main()
