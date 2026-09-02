from __future__ import annotations

from urllib.parse import urlparse

from autoreconx.correlation.models import (
    CorrelatedDomain,
    CorrelatedEndpoint,
    CorrelatedIP,
    CorrelatedPort,
    CorrelatedService,
    CorrelatedWebAsset,
)
from autoreconx.correlation.relationships import (
    AssetRelationship,
    RelationshipType,
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
        key = f"{asset.ip}:{asset.port}/{asset.protocol}"

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
        key = f"{asset.ip}:{asset.port}/{asset.protocol}"

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
        logical.technologies.update(asset.technologies)

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

    build_relationships(result, correlated)
    return correlated


def build_relationships(
    result: ScanResult,
    correlated: CorrelatedScanResult,
) -> None:
    """
    Build relationships that can be safely derived from normalized data.

    Current relationships:
      IP -> Port
      Port -> Service
      Host -> Web Application
      Web Application -> Endpoint
    """

    relationships: dict[
        tuple[str, str, str, str, str],
        AssetRelationship,
    ] = {}

    def add_relationship(
        source_type: str,
        source_id: str,
        relationship: RelationshipType,
        target_type: str,
        target_id: str,
        evidence_source: str,
    ) -> None:
        key = (
            source_type,
            source_id,
            relationship.value,
            target_type,
            target_id,
        )

        relationships.setdefault(
            key,
            AssetRelationship(
                source_type=source_type,
                source_id=source_id,
                relationship=relationship,
                target_type=target_type,
                target_id=target_id,
                evidence_source=evidence_source,
            ),
        )

    # Domain -> IP
    for resolution in result.dns_resolutions:
        add_relationship(
            "domain",
            resolution.hostname,
            RelationshipType.RESOLVES_TO,
            "ip",
            resolution.address,
            resolution.source,
        )

    # IP -> Port
    for port in correlated.ports.values():
        port_id = f"{port.ip}:{port.port}/{port.protocol}"

        add_relationship(
            "ip",
            port.ip,
            RelationshipType.EXPOSES,
            "port",
            port_id,
            "naabu",
        )

    # Port -> Service
    for service in correlated.services.values():
        port_id = f"{service.ip}:{service.port}/{service.protocol}"

        service_id = port_id

        add_relationship(
            "port",
            port_id,
            RelationshipType.RUNS,
            "service",
            service_id,
            "nmap",
        )

    # Host -> Web Application
    for web in correlated.web_assets.values():
        parsed = urlparse(web.url)

        host = parsed.hostname

        if not host:
            continue

        # A web application may be associated with either
        # a domain or a direct IP target.
        source_type = "domain" if host in correlated.domains else "ip"

        add_relationship(
            source_type,
            host,
            RelationshipType.SERVES,
            "web",
            web.url,
            "httpx",
        )

    # Web Application -> Endpoint
    web_urls = tuple(correlated.web_assets.keys())

    for endpoint in correlated.endpoints.values():
        endpoint_parsed = urlparse(endpoint.url)

        best_parent = None

        for web_url in web_urls:
            web_parsed = urlparse(web_url)

            if (
                endpoint_parsed.hostname == web_parsed.hostname
                and endpoint_parsed.scheme == web_parsed.scheme
            ):
                best_parent = web_url
                break

        if not best_parent:
            continue

        add_relationship(
            "web",
            best_parent,
            RelationshipType.CONTAINS,
            "endpoint",
            f"{endpoint.method} {endpoint.url}",
            "katana",
        )

    correlated.relationships = list(relationships.values())
