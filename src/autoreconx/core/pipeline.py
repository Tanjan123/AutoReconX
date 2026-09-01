from __future__ import annotations

from urllib.parse import urlparse

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.httpx_toolkit import (
    build_web_urls,
)
from autoreconx.modules.naabu import (
    filter_ips,
)
from autoreconx.stages.crawl import run_crawl
from autoreconx.stages.discovery import (
    run_dns_resolution,
    run_subfinder,
)
from autoreconx.stages.ports import run_port_discovery
from autoreconx.stages.services import run_service_enumeration
from autoreconx.stages.web import (
    build_hostname_seed_urls,
    build_ip_web_urls,
    run_http_probe,
)


def extract_requested_path(target: str) -> str:
    """Preserve a URL path/query for local web targets such as DVWA."""
    if "://" not in target:
        return "/"

    parsed = urlparse(target)

    path = parsed.path or "/"

    if parsed.query:
        path = f"{path}?{parsed.query}"

    return path


def run_ip_pipeline(
    context: ScanContext,
    *,
    ports: bool,
    services: bool,
    web: bool,
    crawl: bool,
    allow_public: bool,
) -> None:
    """
    Execute the AutoReconX IP/lab reconnaissance pipeline.

    Current flow:
        IP
         ↓
        Naabu
         ↓
        HTTPX (optional)
         ↓
        Nmap (optional)
    """
    scope = context.scope

    requested_path = extract_requested_path(context.original_target)

    # Safety filtering
    scan_ips = filter_ips(
        [scope.target],
        allow_public=allow_public,
    )

    if not scan_ips:
        typer.echo(
            "[warn] target IP is public/global and scanning is disabled by default."
        )
        typer.echo(
            "[hint] use --allow-public only if you are explicitly authorized."
        )
        return

    if not ports:
        typer.echo(
            "[info] IP target detected. "
            "Use --ports to run naabu, and --services for nmap."
        )
        return

    # Naabu
    port_result = run_port_discovery(
        context,
        [scope.target],
        allow_public=allow_public,
    )

    if port_result is None:
        return

    # HTTPX
    open_ports = port_result.open_ports

    web_urls: tuple[str, ...] = ()

    if web or crawl:
        web_urls = build_ip_web_urls(
            scope.target,
            open_ports,
            requested_path=requested_path,
        )

        http_result = run_http_probe(
            context,
            web_urls,
            evidence_name="httpx",
            label="HTTP probing",
        )

        if crawl and http_result is not None:
            confirmed_urls = tuple(
                sorted(
                    {
                        item.url
                        for item in http_result.items
                    }
                )
            )

            run_crawl(
                context,
                confirmed_urls,
                depth=2,
                evidence_name="katana",
            )

    # Nmap
    if services:
        run_service_enumeration(
            context,
            open_ports,
        )
    else:
        typer.echo(
            "[info] service enumeration disabled "
            "(use --services to enable nmap stage)."
        )

def run_domain_pipeline(
    context: ScanContext,
    *,
    ports: bool,
    services: bool,
    web: bool,
    crawl: bool,
    allow_public: bool,
) -> None:
    """
    Execute the AutoReconX domain reconnaissance pipeline.

    Current flow:
        Domain
          ↓
        Subfinder
          ↓
        dnsx
          ↓
        HTTPX hostname probing (optional)
          ↓
        Naabu (optional)
          ↓
        HTTPX discovered-port probing (optional)
          ↓
        Nmap service enumeration (optional)
    """


    # Subfinder (passive subdomain discovery)
    subdomains = run_subfinder(context)

    if not subdomains:
        typer.echo("[info] no subdomains discovered; stopping.")
        return

    # DNS resolution
    resolved = run_dns_resolution(
        context,
        subdomains,
    )

    if resolved is None:
        typer.echo(
            "[info] DNS resolution did not complete; stopping."
        )
        return

    # HTTPX hostname probing
    host_seed_urls: tuple[str, ...] = ()
    host_http_result = None

    if web or crawl:
        host_seed_urls = build_hostname_seed_urls(
            resolved.resolved
        )

        host_http_result = run_http_probe(
            context,
            host_seed_urls,
            evidence_name="httpx-hosts",
            label="HTTP probing - hostnames",
        )

        if crawl and host_http_result is not None:
            confirmed_urls = tuple(
                sorted(
                    {
                        item.url
                        for item in host_http_result.items
                    }
                )
            )

            run_crawl(
                context,
                confirmed_urls,
                depth=2,
                evidence_name="katana-hosts",
            )

    # Port discovery is optional
    if not ports:
        typer.echo(
            "[info] port discovery disabled "
            "(use --ports to enable naabu stage)."
        )
        return

    all_ips: list[str] = []

    for host_resolution in resolved.resolved:
        all_ips.extend(host_resolution.ips)

    scan_ips = filter_ips(
        all_ips,
        allow_public=allow_public,
    )

    if not scan_ips:
        typer.echo(
            "[warn] no IPs eligible for scanning "
            "(private-only by default)."
        )
        typer.echo(
            "[hint] use --allow-public only if "
            "you are explicitly authorized."
        )
        return

    # Naabu
    port_result = run_port_discovery(
        context,
        all_ips,
        allow_public=allow_public,
    )

    if port_result is None:
        return

    open_ports = port_result.open_ports

    # Second HTTPX pass for web ports found by Naabu
    if web:
        discovered_urls = set(
            build_web_urls(
                resolved.resolved,
                open_ports,
            )
        )

        extra_urls = tuple(
            sorted(
                discovered_urls
                - set(host_seed_urls)
            )
        )

        if extra_urls:
            run_http_probe(
                context,
                extra_urls,
                evidence_name="httpx-ports",
                label="HTTP probing - discovered ports",
            )
        else:
            typer.echo(
                "[info] no additional "
                "web port URLs discovered."
            )

    # Nmap is optional
    if services:
        run_service_enumeration(
            context,
            open_ports,
        )
    else:
        typer.echo(
            "[info] service enumeration disabled "
            "(use --services to enable nmap stage)."
        )
