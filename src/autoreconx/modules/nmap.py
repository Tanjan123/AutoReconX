from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree as ET


@dataclass(frozen=True)
class NmapService:
    ip: str
    port: int
    protocol: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None


@dataclass(frozen=True)
class NmapResult:
    services: tuple[NmapService, ...]


def build_nmap_args(ip: str, ports: list[int], *, xml_out: str) -> list[str]:
    """
    Safe, targeted service scan:
    -sT: connect scan (no root required)
    -sV: version detection
    -Pn: skip host discovery (we already have resolved IPs)
    --open: show only open ports
    -p: only the ports we discovered
    -oX: XML output for stable parsing
    """
    ports_str = ",".join(str(p) for p in sorted(set(ports)))
    return [
        "nmap",
        "-sT",
        "-sV",
        "-Pn",
        "-p",
        ports_str,
        "-oX",
        xml_out,
        ip,
    ]


def parse_nmap_xml(xml_text: str) -> NmapResult:
    root = ET.fromstring(xml_text)
    services: list[NmapService] = []

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        if not ip:
            continue

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            proto = port_el.get("protocol") or "tcp"
            portid = port_el.get("portid")
            if not portid:
                continue
            try:
                port = int(portid)
            except ValueError:
                continue

            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc = port_el.find("service")
            if svc is not None:
                services.append(
                    NmapService(
                        ip=ip,
                        port=port,
                        protocol=proto,
                        service=svc.get("name"),
                        product=svc.get("product"),
                        version=svc.get("version"),
                        extrainfo=svc.get("extrainfo"),
                    )
                )
            else:
                services.append(NmapService(ip=ip, port=port, protocol=proto))

    return NmapResult(services=tuple(services))
