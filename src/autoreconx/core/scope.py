from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional
from urllib.parse import urlparse


class TargetKind(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _extract_host(value: str) -> str:
    """
    Accepts: domain, ip, cidr, or URL-like input.
    Returns: host/cidr string for validation.
    """
    v = value.strip()

    # If user pasted a URL, extract netloc.
    if "://" in v:
        parsed = urlparse(v)
        host = parsed.netloc
        if not host:
            raise ValueError("Invalid URL input. Provide a domain/IP/CIDR.")
        # strip credentials if any (user:pass@host)
        if "@" in host:
            host = host.split("@", 1)[1]
        # strip port
        if ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        # handle [ipv6]:port
        if host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        return host.strip().rstrip(".").lower()

    return v.rstrip(".").lower()


def is_valid_domain(domain: str) -> bool:
    d = domain.strip().rstrip(".").lower()
    return bool(_DOMAIN_RE.match(d))


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def is_subdomain_of(child: str, parent: str) -> bool:
    c = normalize_domain(child)
    p = normalize_domain(parent)
    return c == p or c.endswith("." + p)


@dataclass(frozen=True)
class Scope:
    kind: TargetKind
    target: str

    # exclusions (optional)
    exclude_domains: tuple[str, ...] = ()
    exclude_networks: tuple[ipaddress._BaseNetwork, ...] = ()

    def allows_domain(self, domain: str) -> bool:
        d = normalize_domain(domain)

        # exclusions first
        for ex in self.exclude_domains:
            if is_subdomain_of(d, ex):
                return False

        if self.kind == TargetKind.DOMAIN:
            return is_subdomain_of(d, self.target)

        # If user scoped by IP/CIDR, domain checks are not meaningful
        return True

    def allows_ip(self, ip: str) -> bool:
        ip_obj = ipaddress.ip_address(ip)

        # exclusions first
        for net in self.exclude_networks:
            if ip_obj in net:
                return False

        if self.kind == TargetKind.IP:
            return ip_obj == ipaddress.ip_address(self.target)

        if self.kind == TargetKind.CIDR:
            return ip_obj in ipaddress.ip_network(self.target, strict=False)

        # DOMAIN scope: IP policy is tricky (CDNs/third-party hosting).
        # V1: allow IPs only if they are derived from in-scope domains.
        # (Actual enforcement will happen later in module runner logic.)
        return True


def parse_scope(
    raw_target: str,
    *,
    exclude: Optional[Iterable[str]] = None,
) -> Scope:
    """
    Build a Scope object from a user-provided target and optional exclusions.
    Supports: domain, IP, CIDR (also accepts URL-like input and extracts host).
    """
    target = _extract_host(raw_target)

    # Determine target type
    kind: TargetKind
    try:
        ipaddress.ip_address(target)
        kind = TargetKind.IP
    except ValueError:
        try:
            ipaddress.ip_network(target, strict=False)
            kind = TargetKind.CIDR
        except ValueError:
            if not is_valid_domain(target):
                raise ValueError(
                    "Invalid target. Provide a domain (example.com), IP (1.2.3.4) or CIDR (1.2.3.0/24)."
                )
            kind = TargetKind.DOMAIN

    # Parse exclusions
    ex_domains: list[str] = []
    ex_networks: list[ipaddress._BaseNetwork] = []

    if exclude:
        for item in exclude:
            x = _extract_host(item)
            # domain exclusion
            if is_valid_domain(x):
                ex_domains.append(normalize_domain(x))
                continue
            # ip/cidr exclusion
            try:
                # if it's an IP, convert to /32 or /128
                ip_obj = ipaddress.ip_address(x)
                net = ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False)
                ex_networks.append(net)
                continue
            except ValueError:
                pass

            try:
                ex_networks.append(ipaddress.ip_network(x, strict=False))
                continue
            except ValueError:
                raise ValueError(f"Invalid exclude entry: {item}")

    # normalize target if domain
    if kind == TargetKind.DOMAIN:
        target = normalize_domain(target)

    return Scope(
        kind=kind,
        target=target,
        exclude_domains=tuple(sorted(set(ex_domains))),
        exclude_networks=tuple(ex_networks),
    )
