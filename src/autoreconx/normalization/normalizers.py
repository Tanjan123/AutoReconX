from __future__ import annotations

from collections.abc import Iterable

from autoreconx.models import (
    DomainAsset,
    EndpointAsset,
    IPAsset,
    PortAsset,
    ServiceAsset,
    WebAsset,
)
from autoreconx.modules.dnsx import HostResolution
from autoreconx.modules.httpx_toolkit import HttpxItem
from autoreconx.modules.katana import KatanaEndpoint
from autoreconx.modules.naabu import OpenPort
from autoreconx.modules.nmap import NmapService


def normalize_subdomains(
    subdomains: Iterable[str],
) -> list[DomainAsset]:
    """Convert discovered subdomains into normalized domain assets."""

    unique = {
        hostname.strip().lower().rstrip(".")
        for hostname in subdomains
        if hostname.strip()
    }

    return [
        DomainAsset(
            hostname=hostname,
            source="subfinder",
        )
        for hostname in sorted(unique)
    ]


def normalize_resolutions(
    resolutions: Iterable[HostResolution],
) -> tuple[list[DomainAsset], list[IPAsset]]:
    """
    Convert dnsx host/IP relationships into normalized assets.

    Relationship storage is added separately later.
    """

    domains: dict[str, DomainAsset] = {}
    ips: dict[str, IPAsset] = {}

    for resolution in resolutions:
        hostname = resolution.host.strip().lower().rstrip(".")

        if hostname:
            domains[hostname] = DomainAsset(
                hostname=hostname,
                source="dnsx",
            )

        for address in resolution.ips:
            address = address.strip()

            if address:
                ips[address] = IPAsset(
                    address=address,
                    source="dnsx",
                )

    return (
        [domains[key] for key in sorted(domains)],
        [ips[key] for key in sorted(ips)],
    )


def normalize_ports(
    open_ports: Iterable[OpenPort],
) -> list[PortAsset]:
    """Convert Naabu results into normalized port assets."""

    unique = {
        (item.ip.strip(), item.port)
        for item in open_ports
        if item.ip.strip()
    }

    return [
        PortAsset(
            ip=ip,
            port=port,
            protocol="tcp",
            source="naabu",
        )
        for ip, port in sorted(unique)
    ]


def normalize_services(
    services: Iterable[NmapService],
) -> list[ServiceAsset]:
    """Convert Nmap services into normalized service assets."""

    unique: dict[
        tuple[str, int, str],
        ServiceAsset,
    ] = {}

    for item in services:
        key = (
            item.ip,
            item.port,
            item.protocol,
        )

        unique[key] = ServiceAsset(
            ip=item.ip,
            port=item.port,
            protocol=item.protocol,
            service=item.service,
            product=item.product,
            version=item.version,
            source="nmap",
        )

    return [
        unique[key]
        for key in sorted(unique)
    ]


def normalize_web_assets(
    items: Iterable[HttpxItem],
) -> list[WebAsset]:
    """
    Convert HTTPX results into normalized web assets.

    Duplicate final URLs collapse into one logical web asset.
    """

    unique: dict[str, WebAsset] = {}

    for item in items:
        url = item.url.strip()

        if not url:
            continue

        unique[url] = WebAsset(
            url=url,
            status_code=item.status_code,
            title=item.title,
            webserver=item.webserver,
            technologies=item.tech,
            source="httpx",
        )

    return [
        unique[url]
        for url in sorted(unique)
    ]


def normalize_endpoints(
    endpoints: Iterable[KatanaEndpoint],
) -> list[EndpointAsset]:
    """Convert Katana results into normalized endpoint assets."""

    unique: dict[
        tuple[str, str],
        EndpointAsset,
    ] = {}

    for item in endpoints:
        url = item.url.strip()

        if not url:
            continue

        method = item.method.upper().strip() or "GET"

        key = (method, url)

        unique[key] = EndpointAsset(
            url=url,
            method=method,
            host=item.host,
            path=item.path,
            source="katana",
        )

    return [
        unique[key]
        for key in sorted(unique)
    ]
