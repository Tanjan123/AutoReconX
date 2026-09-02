from __future__ import annotations

from dataclasses import dataclass, field

from autoreconx.correlation.models import (
    CorrelatedDomain,
    CorrelatedEndpoint,
    CorrelatedIP,
    CorrelatedPort,
    CorrelatedService,
    CorrelatedWebAsset,
)
from autoreconx.correlation.relationships import AssetRelationship


@dataclass
class CorrelatedScanResult:
    scan_id: str
    target: str

    domains: dict[str, CorrelatedDomain] = field(default_factory=dict)

    ips: dict[str, CorrelatedIP] = field(default_factory=dict)

    ports: dict[str, CorrelatedPort] = field(default_factory=dict)

    services: dict[str, CorrelatedService] = field(default_factory=dict)

    web_assets: dict[str, CorrelatedWebAsset] = field(default_factory=dict)

    endpoints: dict[str, CorrelatedEndpoint] = field(default_factory=dict)

    relationships: list[AssetRelationship] = field(default_factory=list)
