from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


@dataclass(frozen=True)
class DomainAsset:
    """
    Normalized domain/hostname discovered during reconnaissance.
    """

    hostname: str
    source: str
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class IPAsset:
    """
    Normalized IP address associated with the attack surface.
    """

    address: str
    source: str
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class PortAsset:
    """
    Normalized exposed network port.
    """

    ip: str
    port: int
    protocol: str = "tcp"
    source: str = "unknown"
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class ServiceAsset:
    """
    Normalized network service identified on a port.
    """

    ip: str
    port: int
    protocol: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    source: str = "unknown"
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class WebAsset:
    """
    Normalized HTTP/HTTPS application.
    """

    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: tuple[str, ...] = ()
    source: str = "unknown"
    discovered_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class EndpointAsset:
    """
    Normalized web endpoint/resource discovered by crawling.
    """

    url: str
    method: str = "GET"
    host: str | None = None
    path: str | None = None
    source: str = "unknown"
    discovered_at: datetime = field(default_factory=utc_now)
