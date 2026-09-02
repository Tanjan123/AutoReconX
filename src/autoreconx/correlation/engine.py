from __future__ import annotations

from autoreconx.correlation.models import (
    CorrelatedDomain,
    CorrelatedEndpoint,
    CorrelatedIP,
    CorrelatedPort,
    CorrelatedService,
    CorrelatedWebAsset,
)
from autoreconx.correlation.result import CorrelatedScanResult
from autoreconx.models import ScanResult


def correlate_scan(
    result: ScanResult,
) -> CorrelatedScanResult:
    """
    Deduplicate normalized observations into logical assets while
    preserving source provenance.
    """

    correlated = CorrelatedScanResult(
        scan_id=result.scan_id,
        target=result.target,
    )

    # Domains
    for asset in result.domains:
        key = asset.hostname.lower().rstrip(".")

        logical = correlated.domains.setdefault(
            key,
            CorrelatedDomain(hostname=key),
        )

        logical.sources.add(asset.source)

    # IP addresses
    for asset in result.ips:
        key = asset.address

        logical = correlated.ips.setdefault(
            key,
            CorrelatedIP(address=key),
        )

        logical.sources.add(asset.source)

    # Ports
    for asset in result.ports:
        key = (
            f"{asset.ip}:{asset.port}/"
            f"{asset.protocol}"
        )

        logical = correlated.ports.setdefault(
            key,
            CorrelatedPort(
                ip=asset.ip,
                port=asset.port,
                protocol=asset.protocol,
            ),
        )

        logical.sources.add(asset.source)

    # Services
    for asset in result.services:
        key = (
            f"{asset.ip}:{asset.port}/"
            f"{asset.protocol}"
        )

        logical = correlated.services.setdefault(
            key,
            CorrelatedService(
                ip=asset.ip,
                port=asset.port,
                protocol=asset.protocol,
                service=asset.service,
                product=asset.product,
                version=asset.version,
            ),
        )

        logical.sources.add(asset.source)

    # Web applications
    for asset in result.web_assets:
        key = asset.url

        logical = correlated.web_assets.setdefault(
            key,
            CorrelatedWebAsset(
                url=asset.url,
                status_code=asset.status_code,
                title=asset.title,
                webserver=asset.webserver,
            ),
        )

        logical.sources.add(asset.source)
        logical.technologies.update(
            asset.technologies
        )

    # Endpoints
    for asset in result.endpoints:
        method = asset.method.upper()
        key = f"{method} {asset.url}"

        logical = correlated.endpoints.setdefault(
            key,
            CorrelatedEndpoint(
                url=asset.url,
                method=method,
                host=asset.host,
                path=asset.path,
            ),
        )

        logical.sources.add(asset.source)

    return correlated
