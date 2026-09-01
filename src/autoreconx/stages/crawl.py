from __future__ import annotations

from urllib.parse import urlparse

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.dnsx import write_lines
from autoreconx.modules.katana import (
    KatanaEndpoint,
    build_katana_args,
    parse_katana_output,
)
from autoreconx.normalization import normalize_endpoints


def _allowed_hosts(seed_urls: tuple[str, ...]) -> set[str]:
    """Extract permitted hostnames from crawler seed URLs."""

    hosts: set[str] = set()

    for url in seed_urls:
        parsed = urlparse(url)

        if parsed.hostname:
            hosts.add(parsed.hostname.lower())

    return hosts


def run_crawl(
    context: ScanContext,
    urls: tuple[str, ...],
    *,
    depth: int = 2,
    evidence_name: str = "katana",
) -> tuple[KatanaEndpoint, ...]:
    """
    Crawl authorized web URLs using Katana.

    Only endpoints belonging to the original seed hosts are retained.
    """

    raw_dir = context.raw_dir
    runner = context.runner

    seed_urls = tuple(
        sorted(
            {
                url.strip()
                for url in urls
                if isinstance(url, str) and url.strip()
            }
        )
    )

    if not seed_urls:
        typer.echo("[info] no URLs available for crawling.")
        return ()

    allowed_hosts = _allowed_hosts(seed_urls)

    urls_file = raw_dir / f"{evidence_name}-urls.txt"

    write_lines(
        str(urls_file),
        seed_urls,
    )

    typer.echo(
        f"[run] katana (web crawling) "
        f"urls={len(seed_urls)} depth={depth}"
    )

    args = build_katana_args(
        str(urls_file),
        depth=depth,
    )

    try:
        result = runner.run(
            args,
            timeout=600,
            stdout_path=str(
                raw_dir / f"{evidence_name}.jsonl"
            ),
            stderr_path=str(
                raw_dir / f"{evidence_name}.err"
            ),
        )
    except FileNotFoundError as exc:
        typer.echo(f"[warn] {exc}")
        typer.echo(
            "[hint] install ProjectDiscovery katana "
            "and ensure it is in PATH"
        )
        return ()

    if result.timed_out:
        typer.echo("[warn] katana timed out")
        return ()

    if result.returncode != 0:
        typer.echo(
            f"[warn] katana failed "
            f"(rc={result.returncode})"
        )

        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])

        return ()

    parsed = parse_katana_output(
        result.stdout
    )

    filtered: list[KatanaEndpoint] = []

    for endpoint in parsed.endpoints:
        if endpoint.host in allowed_hosts:
            filtered.append(endpoint)

    endpoints = tuple(filtered)

    typer.echo(
        f"[ok] endpoints discovered: "
        f"{len(endpoints)}"
    )

    for endpoint in endpoints[:15]:
        typer.echo(
            f" - {endpoint.method} {endpoint.url}"
        )

    typer.echo(
        f"[saved] katana raw output: "
        f"{raw_dir / f'{evidence_name}.jsonl'}"
    )

    context.result.endpoints.extend(
        normalize_endpoints(endpoints)
    )

    return endpoints
