from __future__ import annotations

from urllib.parse import urlparse

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.dnsx import write_lines
from autoreconx.modules.httpx_toolkit import (
    build_httpx_toolkit_args,
    parse_httpx_output,
)
from autoreconx.modules.naabu import (
    build_naabu_args,
    filter_ips,
    parse_naabu_output,
)
from autoreconx.modules.nmap import build_nmap_args, parse_nmap_xml


def extract_requested_path(target: str) -> str:
    """Preserve a URL path/query for local web targets such as DVWA."""
    if "://" not in target:
        return "/"

    parsed = urlparse(target)

    path = parsed.path or "/"

    if parsed.query:
        path = f"{path}?{parsed.query}"

    return path


def run_ip_pipeline(
    context: ScanContext,
    *,
    ports: bool,
    services: bool,
    web: bool,
    allow_public: bool,
) -> None:
    """
    Execute the AutoReconX IP/lab reconnaissance pipeline.

    Current flow:
        IP
         ↓
        Naabu
         ↓
        HTTPX (optional)
         ↓
        Nmap (optional)
    """

    scope = context.scope
    raw_dir = context.raw_dir
    runner = context.runner

    requested_path = extract_requested_path(context.original_target)

    # Safety filtering
    scan_ips = filter_ips(
        [scope.target],
        allow_public=allow_public,
    )

    if not scan_ips:
        typer.echo(
            "[warn] target IP is public/global and scanning is disabled by default."
        )
        typer.echo(
            "[hint] use --allow-public only if you are explicitly authorized."
        )
        return

    if not ports:
        typer.echo(
            "[info] IP target detected. "
            "Use --ports to run naabu, and --services for nmap."
        )
        return

    # Naabu
    typer.echo(
        f"[run] naabu (port discovery) "
        f"targets={len(scan_ips)} allow_public={allow_public}"
    )

    ips_file = raw_dir / "ips.txt"
    write_lines(str(ips_file), scan_ips)

    naabu_args = build_naabu_args(
        str(ips_file),
        top_ports=1000,
        rate=200,
    )

    try:
        naabu_res = runner.run(
            naabu_args,
            timeout=600,
            stdout_path=str(raw_dir / "naabu.jsonl"),
            stderr_path=str(raw_dir / "naabu.err"),
        )
    except FileNotFoundError as exc:
        typer.echo(f"[warn] {exc}")
        typer.echo("[hint] install naabu and ensure it is in PATH")
        return

    if naabu_res.timed_out:
        typer.echo("[warn] naabu timed out")
        return

    if naabu_res.returncode != 0:
        typer.echo(
            f"[warn] naabu failed (rc={naabu_res.returncode})"
        )

        if naabu_res.stderr.strip():
            typer.echo(naabu_res.stderr.strip()[:500])

        return

    open_ports = parse_naabu_output(naabu_res.stdout)

    typer.echo(
        f"[ok] open ports found: {len(open_ports.open_ports)}"
    )

    for item in open_ports.open_ports[:10]:
        typer.echo(f" - {item.ip}:{item.port}")

    # HTTPX
    if web:
        web_ports = {
            80,
            443,
            3000,
            5000,
            8000,
            8080,
            8443,
        }

        urls: list[str] = []

        for item in open_ports.open_ports:
            if item.port not in web_ports:
                continue

            scheme = (
                "https"
                if item.port in {443, 8443}
                else "http"
            )

            if (
                (scheme == "http" and item.port == 80)
                or
                (scheme == "https" and item.port == 443)
            ):
                base = f"{scheme}://{item.ip}"
            else:
                base = f"{scheme}://{item.ip}:{item.port}"

            urls.append(base + requested_path)

        if not urls:
            typer.echo(
                "[info] no known web ports found "
                "to probe with httpx-toolkit."
            )
        else:
            urls_file = raw_dir / "urls.txt"
            write_lines(str(urls_file), urls)

            typer.echo(
                f"[run] httpx-toolkit "
                f"(HTTP probing) urls={len(urls)}"
            )

            httpx_args = build_httpx_toolkit_args(
                str(urls_file)
            )

            try:
                httpx_res = runner.run(
                    httpx_args,
                    timeout=300,
                    stdout_path=str(
                        raw_dir / "httpx.jsonl"
                    ),
                    stderr_path=str(
                        raw_dir / "httpx.err"
                    ),
                )
            except FileNotFoundError as exc:
                typer.echo(f"[warn] {exc}")
                typer.echo(
                    "[hint] install ProjectDiscovery "
                    "httpx-toolkit and ensure it is in PATH"
                )
            else:
                if httpx_res.timed_out:
                    typer.echo(
                        "[warn] httpx-toolkit timed out"
                    )

                elif httpx_res.returncode != 0:
                    typer.echo(
                        f"[warn] httpx-toolkit failed "
                        f"(rc={httpx_res.returncode})"
                    )

                    if httpx_res.stderr.strip():
                        typer.echo(
                            httpx_res.stderr.strip()[:500]
                        )

                else:
                    parsed_http = parse_httpx_output(
                        httpx_res.stdout
                    )

                    typer.echo(
                        f"[ok] httpx results: "
                        f"{len(parsed_http.items)}"
                    )

                    for item in parsed_http.items[:10]:
                        title = item.title or ""
                        server = item.webserver or ""

                        typer.echo(
                            f" - {item.url} "
                            f"[{item.status_code}] "
                            f"{title} {server}".rstrip()
                        )

                        if item.tech:
                            typer.echo(
                                f"   tech: "
                                f"{', '.join(item.tech)}"
                            )

                    typer.echo(
                        f"[saved] httpx raw output: "
                        f"{raw_dir / 'httpx.jsonl'}"
                    )

    # Nmap
    if not services:
        typer.echo(
            "[info] service enumeration disabled "
            "(use --services to enable nmap stage)."
        )
        return

    if not open_ports.open_ports:
        typer.echo(
            "[info] no open ports available "
            "for nmap service enumeration."
        )
        return

    ports_by_ip: dict[str, list[int]] = {}

    for item in open_ports.open_ports:
        ports_by_ip.setdefault(
            item.ip,
            [],
        ).append(item.port)

    typer.echo(
        f"[run] nmap (service enumeration) "
        f"hosts={len(ports_by_ip)}"
    )

    for ip, port_list in ports_by_ip.items():
        typer.echo(
            f"[run] nmap {ip} "
            f"ports={sorted(set(port_list))}"
        )

        xml_path = raw_dir / f"nmap-{ip}.xml"

        nmap_args = build_nmap_args(
            ip,
            port_list,
            xml_out=str(xml_path),
        )

        try:
            nmap_res = runner.run(
                nmap_args,
                timeout=900,
                stdout_path=str(
                    raw_dir / f"nmap-{ip}.stdout"
                ),
                stderr_path=str(
                    raw_dir / f"nmap-{ip}.err"
                ),
            )
        except FileNotFoundError as exc:
            typer.echo(f"[warn] {exc}")
            continue

        if nmap_res.timed_out:
            typer.echo(
                f"[warn] nmap timed out for {ip}"
            )
            continue

        if nmap_res.returncode != 0:
            typer.echo(
                f"[warn] nmap failed for {ip} "
                f"(rc={nmap_res.returncode})"
            )
            continue

        if not xml_path.exists():
            typer.echo(
                f"[warn] nmap XML output missing for {ip}"
            )
            continue

        xml_text = xml_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        nmap_parsed = parse_nmap_xml(xml_text)

        typer.echo(
            f"[ok] {ip} services(open-only): "
            f"{len(nmap_parsed.services)}"
        )

        for service in nmap_parsed.services[:10]:
            name = service.service or "unknown"

            typer.echo(
                f" - {service.ip}:{service.port}/"
                f"{service.protocol} {name}"
            )
