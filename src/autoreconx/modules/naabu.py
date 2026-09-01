from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class OpenPort:
    ip: str
    port: int


@dataclass(frozen=True)
class NaabuResult:
    open_ports: tuple[OpenPort, ...]


def filter_ips(ips: Iterable[str], *, allow_public: bool) -> list[str]:
    out: list[str] = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue

        if allow_public:
            out.append(str(ip_obj))
        else:
            if not ip_obj.is_global:
                out.append(str(ip_obj))
    return sorted(set(out))


def build_naabu_args(input_file: str, *, top_ports: int = 100, rate: int = 200) -> list[str]:
    """
    Use JSON lines for stable parsing.
    Keep defaults conservative.
    """
    return [
        "naabu",
        "-silent",
        "-json",
        "-l",
        input_file,
        "-top-ports",
        str(top_ports),
        "-rate",
        str(rate),
    ]


def parse_naabu_output(output: str) -> NaabuResult:
    """
    Parse naabu JSON lines output.

    Naabu versions may emit:
      {"ip":"1.2.3.4","port":80,...}
    or:
      {"host":"1.2.3.4","port":80,...}
    """
    found: set[tuple[str, int]] = set()

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if not (line.startswith("{") and line.endswith("}")):
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = obj.get("host") or obj.get("ip")
        port = obj.get("port")

        if isinstance(host, str):
            host = host.strip()

        # sometimes port can be string in some outputs
        if isinstance(port, str) and port.isdigit():
            port = int(port)

        if isinstance(host, str) and host and isinstance(port, int):
            found.add((host, port))

    open_ports = tuple(OpenPort(ip=h, port=p) for h, p in sorted(found))
    return NaabuResult(open_ports=open_ports)
