from __future__ import annotations

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.dnsx import write_lines
from autoreconx.modules.httpx_toolkit import (
    HttpxResult,
    build_httpx_toolkit_args,
    parse_httpx_output,
)
from autoreconx.normalization import normalize_web_assets


def run_http_probe(
    context: ScanContext,
    urls: list[str] | tuple[str, ...],
    *,
    evidence_name: str = "httpx",
    label: str = "HTTP probing",
) -> HttpxResult | None:
    """
    Probe candidate web URLs using ProjectDiscovery httpx-toolkit.

    The pipeline decides which URLs should be tested.
    This stage handles execution, evidence and parsing.
    """

    raw_dir = context.raw_dir
    runner = context.runner

    unique_urls = sorted(
        {url.strip() for url in urls if isinstance(url, str) and url.strip()}
    )

    if not unique_urls:
        typer.echo("[info] no URLs available for HTTP probing.")
        return None

    urls_file = raw_dir / f"{evidence_name}-urls.txt"

    write_lines(
        str(urls_file),
        unique_urls,
    )

    typer.echo(f"[run] httpx-toolkit ({label}) urls={len(unique_urls)}")

    args = build_httpx_toolkit_args(str(urls_file))

    try:
        result = runner.run(
            args,
            timeout=300,
            stdout_path=str(raw_dir / f"{evidence_name}.jsonl"),
            stderr_path=str(raw_dir / f"{evidence_name}.err"),
        )
    except FileNotFoundError as exc:
        typer.echo(f"[warn] {exc}")
        typer.echo(
            "[hint] install ProjectDiscovery httpx-toolkit and ensure it is in PATH"
        )
        return None

    if result.timed_out:
        typer.echo(f"[warn] httpx-toolkit timed out ({label})")
        return None

    if result.returncode != 0:
        typer.echo(f"[warn] httpx-toolkit failed (rc={result.returncode})")

        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])

        return None

    parsed = parse_httpx_output(result.stdout)

    typer.echo(f"[ok] httpx results: {len(parsed.items)}")

    for item in parsed.items[:10]:
        title = item.title or ""
        server = item.webserver or ""

        typer.echo(f" - {item.url} [{item.status_code}] {title} {server}".rstrip())

        if item.tech:
            typer.echo("   tech: " + ", ".join(item.tech))

    typer.echo(f"[saved] httpx raw output: {raw_dir / f'{evidence_name}.jsonl'}")

    context.result.web_assets.extend(normalize_web_assets(parsed.items))

    return parsed


def build_ip_web_urls(
    ip: str,
    open_ports,
    *,
    requested_path: str = "/",
) -> tuple[str, ...]:
    """
    Build web URLs for an IP/lab target from discovered ports.
    """

    web_ports = {
        80,
        443,
        3000,
        5000,
        8000,
        8080,
        8443,
    }

    urls: set[str] = set()

    for item in open_ports:
        if item.port not in web_ports:
            continue

        scheme = "https" if item.port in {443, 8443} else "http"

        if (scheme == "http" and item.port == 80) or (
            scheme == "https" and item.port == 443
        ):
            base = f"{scheme}://{ip}"
        else:
            base = f"{scheme}://{ip}:{item.port}"

        urls.add(base + requested_path)

    return tuple(sorted(urls))


def build_hostname_seed_urls(
    resolved_hosts,
) -> tuple[str, ...]:
    """
    Build HTTP/HTTPS seed URLs from resolved hostnames.
    """

    urls: set[str] = set()

    for item in resolved_hosts:
        urls.add(f"http://{item.host}")
        urls.add(f"https://{item.host}")

    return tuple(sorted(urls))
