from __future__ import annotations

from dataclasses import dataclass

from autoreconx.core.scope import is_valid_domain, normalize_domain


@dataclass(frozen=True)
class SubfinderResult:
    subdomains: tuple[str, ...]


def parse_subfinder_stdout(stdout: str, *, root_domain: str) -> SubfinderResult:
    """
    Parse subfinder stdout (newline-separated hostnames).
    Keep only valid domains and only those under root_domain.
    """
    root = normalize_domain(root_domain)
    found: set[str] = set()

    for line in stdout.splitlines():
        s = line.strip().lower().rstrip(".")
        if not s:
            continue
        if not is_valid_domain(s):
            continue
        if s == root or s.endswith("." + root):
            found.add(s)

    return SubfinderResult(subdomains=tuple(sorted(found)))


def build_subfinder_args(domain: str) -> list[str]:
    # Keep V1 simple and stable: stdout lines + silent mode
    return ["subfinder", "-silent", "-d", domain]
