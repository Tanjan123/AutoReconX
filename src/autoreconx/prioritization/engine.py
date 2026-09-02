from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from autoreconx.correlation import CorrelatedScanResult


class PriorityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class PriorityItem:
    asset_type: str
    asset_id: str
    score: int
    level: PriorityLevel
    reasons: tuple[str, ...]


def _priority_level(score: int) -> PriorityLevel:
    if score >= 40:
        return PriorityLevel.HIGH

    if score >= 20:
        return PriorityLevel.MEDIUM

    return PriorityLevel.LOW


def prioritize_scan(
    result: CorrelatedScanResult,
) -> tuple[PriorityItem, ...]:
    """
    Apply transparent reconnaissance-priority rules.

    Priority means "interesting for manual investigation",
    not "confirmed vulnerable".
    """

    items: list[PriorityItem] = []

    interesting_hostname_words = {
        "admin": 30,
        "api": 20,
        "dev": 20,
        "staging": 20,
        "test": 10,
        "internal": 30,
        "vpn": 20,
    }

    # Domains
    for domain in result.domains.values():
        score = 0
        reasons: list[str] = []

        labels = set(
            domain.hostname.lower().split(".")
        )

        for word, points in interesting_hostname_words.items():
            if word in labels:
                score += points
                reasons.append(
                    f"Interesting hostname indicator: {word}"
                )

        if score:
            items.append(
                PriorityItem(
                    asset_type="domain",
                    asset_id=domain.hostname,
                    score=score,
                    level=_priority_level(score),
                    reasons=tuple(reasons),
                )
            )

    # Services
    interesting_services = {
        "mysql": 25,
        "postgresql": 25,
        "mongodb": 25,
        "redis": 25,
        "rdp": 20,
        "ssh": 10,
        "ftp": 15,
        "smb": 20,
    }

    for service in result.services.values():
        name = (
            service.service or ""
        ).lower()

        score = interesting_services.get(
            name,
            0,
        )

        if score:
            items.append(
                PriorityItem(
                    asset_type="service",
                    asset_id=(
                        f"{service.ip}:"
                        f"{service.port}/"
                        f"{service.protocol}"
                    ),
                    score=score,
                    level=_priority_level(score),
                    reasons=(
                        f"Interesting exposed service: {name}",
                    ),
                )
            )

    # Web applications
    for web in result.web_assets.values():
        score = 5
        reasons = [
            "Live web application",
        ]

        parsed = urlparse(web.url)

        hostname = (
            parsed.hostname or ""
        ).lower()

        if hostname.startswith("admin."):
            score += 30
            reasons.append(
                "Administrative web hostname"
            )

        if hostname.startswith("api."):
            score += 20
            reasons.append(
                "API web hostname"
            )

        tech_lower = {
            tech.lower()
            for tech in web.technologies
        }

        if any(
            "swagger" in tech
            for tech in tech_lower
        ):
            score += 15
            reasons.append(
                "API documentation technology detected"
            )

        items.append(
            PriorityItem(
                asset_type="web",
                asset_id=web.url,
                score=score,
                level=_priority_level(score),
                reasons=tuple(reasons),
            )
        )

    # Endpoints
    interesting_paths = {
        "admin": 25,
        "login": 15,
        "auth": 15,
        "api": 15,
        "debug": 25,
        "internal": 25,
        "graphql": 20,
    }

    for endpoint in result.endpoints.values():
        path = (
            endpoint.path or ""
        ).lower()

        score = 0
        reasons = []

        for indicator, points in interesting_paths.items():
            if indicator in path:
                score += points
                reasons.append(
                    f"Interesting path indicator: {indicator}"
                )

        if score:
            items.append(
                PriorityItem(
                    asset_type="endpoint",
                    asset_id=endpoint.url,
                    score=score,
                    level=_priority_level(score),
                    reasons=tuple(reasons),
                )
            )

    return tuple(
        sorted(
            items,
            key=lambda item: (
                -item.score,
                item.asset_type,
                item.asset_id,
            ),
        )
    )
