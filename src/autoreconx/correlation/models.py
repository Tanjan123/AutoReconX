from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CorrelatedDomain:
    hostname: str
    sources: set[str] = field(default_factory=set)


@dataclass
class CorrelatedIP:
    address: str
    sources: set[str] = field(default_factory=set)


@dataclass
class CorrelatedPort:
    ip: str
    port: int
    protocol: str
    sources: set[str] = field(default_factory=set)


@dataclass
class CorrelatedService:
    ip: str
    port: int
    protocol: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    sources: set[str] = field(default_factory=set)


@dataclass
class CorrelatedWebAsset:
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    technologies: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


@dataclass
class CorrelatedEndpoint:
    url: str
    method: str
    host: str | None = None
    path: str | None = None
    sources: set[str] = field(default_factory=set)
