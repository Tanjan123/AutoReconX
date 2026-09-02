from __future__ import annotations

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.dnsx import write_lines
from autoreconx.modules.naabu import (
    NaabuResult,
    build_naabu_args,
    filter_ips,
    parse_naabu_output,
)
from autoreconx.normalization import normalize_ports


def run_port_discovery(
    context: ScanContext,
    ips: list[str],
    *,
    allow_public: bool,
    top_ports: int = 1000,
    rate: int = 200,
) -> NaabuResult | None:
    """
    Run Naabu port discovery against permitted IP addresses.

    Public/global IPs are excluded unless allow_public is enabled.
    Returns normalized Naabu results or None when the stage cannot run.
    """

    raw_dir = context.raw_dir
    runner = context.runner

    scan_ips = filter_ips(
        ips,
        allow_public=allow_public,
    )

    if not scan_ips:
        typer.echo("[warn] no IPs eligible for port scanning.")

        if not allow_public:
            typer.echo(
                "[hint] public/global IPs are disabled by default; "
                "use --allow-public only when explicitly authorized."
            )

        return None

    typer.echo(
        f"[run] naabu (port discovery) "
        f"targets={len(scan_ips)} "
        f"allow_public={allow_public}"
    )

    ips_file = raw_dir / "ips.txt"

    write_lines(
        str(ips_file),
        scan_ips,
    )

    args = build_naabu_args(
        str(ips_file),
        top_ports=top_ports,
        rate=rate,
    )

    try:
        result = runner.run(
            args,
            timeout=600,
            stdout_path=str(raw_dir / "naabu.jsonl"),
            stderr_path=str(raw_dir / "naabu.err"),
        )
    except FileNotFoundError as exc:
        typer.echo(f"[warn] {exc}")
        typer.echo("[hint] install naabu and ensure it is in PATH")
        return None

    if result.timed_out:
        typer.echo("[warn] naabu timed out")
        return None

    if result.returncode != 0:
        typer.echo(f"[warn] naabu failed (rc={result.returncode})")

        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])

        return None

    parsed = parse_naabu_output(result.stdout)

    typer.echo(f"[ok] open ports found: {len(parsed.open_ports)}")

    for item in parsed.open_ports[:10]:
        typer.echo(f" - {item.ip}:{item.port}")

    typer.echo(f"[saved] naabu raw output: {raw_dir / 'naabu.jsonl'}")

    context.result.ports.extend(normalize_ports(parsed.open_ports))

    return parsed
