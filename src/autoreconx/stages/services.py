from __future__ import annotations

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.naabu import OpenPort
from autoreconx.modules.nmap import (
    NmapService,
    build_nmap_args,
    parse_nmap_xml,
)
from autoreconx.normalization import normalize_services


def run_service_enumeration(
    context: ScanContext,
    open_ports: tuple[OpenPort, ...],
) -> tuple[NmapService, ...]:
    """Run targeted Nmap service enumeration on discovered open ports."""

    raw_dir = context.raw_dir
    runner = context.runner

    if not open_ports:
        typer.echo("[info] no open ports available for nmap service enumeration.")
        return ()

    ports_by_ip: dict[str, list[int]] = {}

    for item in open_ports:
        ports_by_ip.setdefault(item.ip, []).append(item.port)

    typer.echo(f"[run] nmap (service enumeration) hosts={len(ports_by_ip)}")

    discovered_services: list[NmapService] = []

    for ip, port_list in ports_by_ip.items():
        unique_ports = sorted(set(port_list))

        typer.echo(f"[run] nmap {ip} ports={unique_ports}")

        xml_path = raw_dir / f"nmap-{ip}.xml"

        args = build_nmap_args(
            ip,
            unique_ports,
            xml_out=str(xml_path),
        )

        try:
            result = runner.run(
                args,
                timeout=900,
                stdout_path=str(raw_dir / f"nmap-{ip}.stdout"),
                stderr_path=str(raw_dir / f"nmap-{ip}.err"),
            )
        except FileNotFoundError as exc:
            typer.echo(f"[warn] {exc}")
            continue

        if result.timed_out:
            typer.echo(f"[warn] nmap timed out for {ip}")
            continue

        if result.returncode != 0:
            typer.echo(f"[warn] nmap failed for {ip} (rc={result.returncode})")
            continue

        if not xml_path.exists():
            typer.echo(f"[warn] nmap XML output missing for {ip}")
            continue

        xml_text = xml_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        parsed = parse_nmap_xml(xml_text)

        typer.echo(f"[ok] {ip} services: {len(parsed.services)}")

        for service in parsed.services[:10]:
            name = service.service or "unknown"

            typer.echo(f" - {service.ip}:{service.port}/{service.protocol} {name}")

        discovered_services.extend(parsed.services)

    context.result.services.extend(normalize_services(discovered_services))

    return tuple(discovered_services)
