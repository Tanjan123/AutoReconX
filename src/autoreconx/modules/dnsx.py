from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass

from autoreconx.core.scope import is_valid_domain, normalize_domain


@dataclass(frozen=True)
class HostResolution:
    host: str
    ips: tuple[str, ...]


@dataclass(frozen=True)
class DnsxResult:
    resolved: tuple[HostResolution, ...]


def build_dnsx_args(input_file: str) -> list[str]:
    """
    Use JSON output for stable parsing.
    -silent: minimal noise
    -json: structured output (one JSON per line)
    -l: input list
    """
    return ["dnsx", "-silent", "-json", "-l", input_file]


def parse_dnsx_output(output: str, *, root_domain: str) -> DnsxResult:
    """
    Parse dnsx output.
    Primary mode: JSON lines.
    Fallback: plain lines (best-effort) if JSON parsing fails.

    Keeps only:
    - valid domains
    - hosts under root_domain
    """
    root = normalize_domain(root_domain)
    resolved_map: dict[str, set[str]] = {}

    def in_scope(host: str) -> bool:
        h = normalize_domain(host)
        return is_valid_domain(h) and (h == root or h.endswith("." + root))

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON first
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = None

            if isinstance(obj, dict):
                host = obj.get("host") or obj.get("hostname") or obj.get("domain")
                if not host or not isinstance(host, str):
                    continue

                host = normalize_domain(host)
                if not in_scope(host):
                    continue

                ips: set[str] = set()

                # dnsx versions may output IPs under different keys
                for key in ("a", "aaaa", "ip", "ips"):
                    val = obj.get(key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, str) and item.strip():
                                ips.add(item.strip())
                    elif isinstance(val, str) and val.strip():
                        ips.add(val.strip())

                if ips:
                    resolved_map.setdefault(host, set()).update(ips)

                continue  # done with JSON line

        # Fallback: plain text best-effort
        # Example formats seen: "host [ip]" or "host ip"
        parts = line.replace("[", " ").replace("]", " ").split()
        if not parts:
            continue
        host = normalize_domain(parts[0])
        if not in_scope(host):
            continue
        ips = {p for p in parts[1:] if p.count(".") >= 1 or ":" in p}
        if ips:
            resolved_map.setdefault(host, set()).update(ips)

    resolved = tuple(
        HostResolution(host=h, ips=tuple(sorted(ips)))
        for h, ips in sorted(resolved_map.items())
    )
    return DnsxResult(resolved=resolved)


def write_lines(path: str, lines: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line)
            f.write("\n")
