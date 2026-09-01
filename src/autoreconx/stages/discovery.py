from __future__ import annotations

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.dnsx import (
    DnsxResult,
    build_dnsx_args,
    parse_dnsx_output,
    write_lines,
)
from autoreconx.modules.subfinder import (
    build_subfinder_args,
    parse_subfinder_stdout,
)
from autoreconx.normalization import (
    normalize_resolutions,
    normalize_subdomains,
)


def run_subfinder(context: ScanContext) -> tuple[str, ...]:
    """
    Run passive subdomain discovery (Subfinder).

    Returns a tuple of discovered subdomains (may be empty).
    """

    scope = context.scope
    raw_dir = context.raw_dir
    runner = context.runner

    typer.echo("[run] subfinder (passive subdomain discovery)")

    args = build_subfinder_args(scope.target)

    try:
        result = runner.run(
            args,
            stdout_path=str(raw_dir / "subfinder.txt"),
            stderr_path=str(raw_dir / "subfinder.err"),
        )
    except FileNotFoundError as exc:
        typer.echo(f"[warn] {exc}")
        typer.echo("[hint] install subfinder and ensure it is in PATH")
        return ()

    if result.timed_out:
        typer.echo("[warn] subfinder timed out")
        return ()

    if result.returncode != 0:
        typer.echo(f"[warn] subfinder failed (rc={result.returncode})")
        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])
        return ()

    parsed = parse_subfinder_stdout(
        result.stdout,
        root_domain=scope.target,
    )

    typer.echo(f"[ok] subdomains discovered: {len(parsed.subdomains)}")

    for subdomain in parsed.subdomains[:10]:
        typer.echo(f" - {subdomain}")

    typer.echo(f"[saved] raw output: {raw_dir / 'subfinder.txt'}")
   
    context.result.domains.extend(
        normalize_subdomains(parsed.subdomains)
    )

    return parsed.subdomains


def run_dns_resolution(
    context: ScanContext,
    subdomains: tuple[str, ...],
) -> DnsxResult | None:
    """
    Resolve discovered subdomains using dnsx.

    Returns normalized DNS resolution results.
    Returns None when execution fails.
    """

    raw_dir = context.raw_dir
    runner = context.runner

    if not subdomains:
        typer.echo("[info] no subdomains available for DNS resolution.")
        return None

    typer.echo("[run] dnsx (DNS resolution)")

    subdomains_file = raw_dir / "subdomains.txt"
    write_lines(
        str(subdomains_file),
        subdomains,
    )

    dnsx_args = build_dnsx_args(
        str(subdomains_file)
    )

    try:
        result = runner.run(
            dnsx_args,
            timeout=600,
            stdout_path=str(raw_dir / "dnsx.jsonl"),
            stderr_path=str(raw_dir / "dnsx.err"),
        )
    except FileNotFoundError as exc:
        typer.echo(f"[warn] {exc}")
        typer.echo(
            "[hint] install dnsx and ensure it is in PATH"
        )
        return None

    if result.timed_out:
        typer.echo("[warn] dnsx timed out")
        return None

    if result.returncode != 0:
        typer.echo(
            f"[warn] dnsx failed (rc={result.returncode})"
        )

        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])

        return None

    resolved = parse_dnsx_output(
        result.stdout,
        root_domain=context.scope.target,
    )

    typer.echo(
        f"[ok] resolved hosts: {len(resolved.resolved)}"
    )

    for item in resolved.resolved[:10]:
        typer.echo(
            f" - {item.host} -> {', '.join(item.ips)}"
        )

    typer.echo(
        f"[saved] dnsx raw output: "
        f"{raw_dir / 'dnsx.jsonl'}"
    )

    normalized_domains, normalized_ips = normalize_resolutions(
        resolved.resolved
    )

    context.result.domains.extend(normalized_domains)
    context.result.ips.extend(normalized_ips)

    return resolved
