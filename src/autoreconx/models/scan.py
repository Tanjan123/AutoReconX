from __future__ import annotations

from dataclasses import dataclass, field

from autoreconx.models.assets import (
    DomainAsset,
    EndpointAsset,
    IPAsset,
    PortAsset,
    ServiceAsset,
    WebAsset,
)


@dataclass
class ScanResult:
    """
    Normalized aggregate result for one AutoReconX scan.

    This becomes the common data structure used by correlation,
    storage and reporting.
    """

    scan_id: str
    target: str

    domains: list[DomainAsset] = field(
        default_factory=list
    )

    ips: list[IPAsset] = field(
        default_factory=list
    )

    ports: list[PortAsset] = field(
        default_factory=list
    )

    services: list[ServiceAsset] = field(
        default_factory=list
    )

    web_assets: list[WebAsset] = field(
        default_factory=list
    )

    endpoints: list[EndpointAsset] = field(
        default_factory=list
    )
