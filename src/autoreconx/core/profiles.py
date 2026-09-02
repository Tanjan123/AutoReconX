from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ScanProfile(str, Enum):
    PASSIVE = "passive"
    STANDARD = "standard"
    FULL = "full"


@dataclass(frozen=True)
class ProfileConfig:
    dns: bool
    ports: bool
    services: bool
    web: bool
    crawl: bool


PROFILES: dict[ScanProfile, ProfileConfig] = {
    ScanProfile.PASSIVE: ProfileConfig(
        dns=False,
        ports=False,
        services=False,
        web=False,
        crawl=False,
    ),
    ScanProfile.STANDARD: ProfileConfig(
        dns=True,
        ports=False,
        services=False,
        web=True,
        crawl=False,
    ),
    ScanProfile.FULL: ProfileConfig(
        dns=True,
        ports=True,
        services=True,
        web=True,
        crawl=True,
    ),
}


def get_profile_config(
    profile: ScanProfile,
) -> ProfileConfig:
    """Return the configuration associated with a scan profile."""

    return PROFILES[profile]
