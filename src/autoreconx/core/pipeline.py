from __future__ import annotations

from urllib.parse import urlparse

import typer

from autoreconx.core.context import ScanContext
from autoreconx.modules.dnsx import (
    write_lines,
)
from autoreconx.modules.httpx_toolkit import (
    build_httpx_toolkit_args,
    build_web_urls,
    parse_httpx_output,
)
from autoreconx.modules.naabu import (
    build_naabu_args,
    filter_ips,
    parse_naabu_output,
)
from autoreconx.modules.nmap import (
    build_nmap_args,
    parse_nmap_xml,
)
from autoreconx.stages.discovery import (
    run_dns_resolution,
    run_subfinder,
)


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

def run_domain_pipeline(
    context: ScanContext,
    *,
    ports: bool,
    services: bool,
    web: bool,
    allow_public: bool,
) -> None:
    """
    Execute the AutoReconX domain reconnaissance pipeline.

    Current flow:
        Domain
          ↓
        Subfinder
          ↓
        dnsx
          ↓
        HTTPX hostname probing (optional)
          ↓
        Naabu (optional)
          ↓
        HTTPX discovered-port probing (optional)
          ↓
        Nmap service enumeration (optional)
    """

    raw_dir = context.raw_dir
    runner = context.runner

    # Subfinder (passive subdomain discovery)
    subdomains = run_subfinder(context)

    if not subdomains:
        typer.echo("[info] no subdomains discovered; stopping.")
        return

    # DNS resolution
    resolved = run_dns_resolution(
        context,
        subdomains,
    )

    if resolved is None:
        typer.echo(
            "[info] DNS resolution did not complete; stopping."
        )
        return

    # HTTPX hostname probing
    host_seed_urls: list[str] = []

    if web:
        seed_urls: set[str] = set()

        for host_resolution in resolved.resolved:
            seed_urls.add(
                f"http://{host_resolution.host}"
            )
            seed_urls.add(
                f"https://{host_resolution.host}"
            )

        host_seed_urls = sorted(seed_urls)

        if host_seed_urls:
            urls_file = raw_dir / "urls-hosts.txt"
            write_lines(
                str(urls_file),
                host_seed_urls,
            )

            typer.echo(
                "[run] httpx-toolkit "
                "(HTTP probing - hostnames) "
                f"urls={len(host_seed_urls)}"
            )

            httpx_args = build_httpx_toolkit_args(
                str(urls_file)
            )

            try:
                httpx_res = runner.run(
                    httpx_args,
                    timeout=300,
                    stdout_path=str(
                        raw_dir / "httpx-hosts.jsonl"
                    ),
                    stderr_path=str(
                        raw_dir / "httpx-hosts.err"
                    ),
                )
            except FileNotFoundError as exc:
                typer.echo(f"[warn] {exc}")
            else:
                if httpx_res.timed_out:
                    typer.echo(
                        "[warn] httpx-toolkit timed out "
                        "(hostnames)"
                    )

                elif httpx_res.returncode != 0:
                    typer.echo(
                        "[warn] httpx-toolkit failed "
                        f"(rc={httpx_res.returncode})"
                    )

                else:
                    http_result = parse_httpx_output(
                        httpx_res.stdout
                    )

                    typer.echo(
                        "[ok] httpx results (hostnames): "
                        f"{len(http_result.items)}"
                    )

                    for item in http_result.items[:10]:
                        title = item.title or ""
                        server = item.webserver or ""

                        typer.echo(
                            f" - {item.url} "
                            f"[{item.status_code}] "
                            f"{title} {server}".rstrip()
                        )

                        if item.tech:
                            typer.echo(
                                "   tech: "
                                + ", ".join(item.tech)
                            )

                    typer.echo(
                        "[saved] httpx raw output: "
                        f"{raw_dir / 'httpx-hosts.jsonl'}"
                    )

    # Port discovery is optional
    if not ports:
        typer.echo(
            "[info] port discovery disabled "
            "(use --ports to enable naabu stage)."
        )
        return

    all_ips: list[str] = []

    for host_resolution in resolved.resolved:
        all_ips.extend(host_resolution.ips)

    scan_ips = filter_ips(
        all_ips,
        allow_public=allow_public,
    )

    if not scan_ips:
        typer.echo(
            "[warn] no IPs eligible for scanning "
            "(private-only by default)."
        )
        typer.echo(
            "[hint] use --allow-public only if "
            "you are explicitly authorized."
        )
        return

    # Naabu
    typer.echo(
        f"[run] naabu (port discovery) "
        f"targets={len(scan_ips)} "
        f"allow_public={allow_public}"
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
        typer.echo(
            "[hint] install naabu and ensure it is in PATH"
        )
        return

    if naabu_res.timed_out:
        typer.echo("[warn] naabu timed out")
        return

    if naabu_res.returncode != 0:
        typer.echo(
            f"[warn] naabu failed "
            f"(rc={naabu_res.returncode})"
        )
        if naabu_res.stderr.strip():
            typer.echo(
                naabu_res.stderr.strip()[:500]
            )
        return

    open_ports = parse_naabu_output(
        naabu_res.stdout
    )

    typer.echo(
        f"[ok] open ports found: "
        f"{len(open_ports.open_ports)}"
    )

    for item in open_ports.open_ports[:10]:
        typer.echo(
            f" - {item.ip}:{item.port}"
        )

    typer.echo(
        f"[saved] naabu raw output: "
        f"{raw_dir / 'naabu.jsonl'}"
    )

    # Second HTTPX pass for web ports found by Naabu
    if web:
        discovered_urls = set(
            build_web_urls(
                resolved.resolved,
                open_ports.open_ports,
            )
        )

        extra_urls = sorted(
            discovered_urls - set(host_seed_urls)
        )

        if extra_urls:
            urls_file = raw_dir / "urls-ports.txt"

            write_lines(
                str(urls_file),
                extra_urls,
            )

            typer.echo(
                "[run] httpx-toolkit "
                "(HTTP probing - discovered ports) "
                f"urls={len(extra_urls)}"
            )

            httpx_args = build_httpx_toolkit_args(
                str(urls_file)
            )

            try:
                httpx_res = runner.run(
                    httpx_args,
                    timeout=300,
                    stdout_path=str(
                        raw_dir / "httpx-ports.jsonl"
                    ),
                    stderr_path=str(
                        raw_dir / "httpx-ports.err"
                    ),
                )
            except FileNotFoundError as exc:
                typer.echo(f"[warn] {exc}")
            else:
                if httpx_res.timed_out:
                    typer.echo(
                        "[warn] httpx-toolkit timed out "
                        "(discovered ports)"
                    )

                elif httpx_res.returncode != 0:
                    typer.echo(
                        "[warn] httpx-toolkit failed "
                        f"(rc={httpx_res.returncode})"
                    )

                else:
                    http_result = parse_httpx_output(
                        httpx_res.stdout
                    )

                    typer.echo(
                        "[ok] httpx results "
                        "(discovered ports): "
                        f"{len(http_result.items)}"
                    )

                    for item in http_result.items[:10]:
                        title = item.title or ""

                        typer.echo(
                            f" - {item.url} "
                            f"[{item.status_code}] "
                            f"{title}".rstrip()
                        )

                    typer.echo(
                        "[saved] httpx raw output: "
                        f"{raw_dir / 'httpx-ports.jsonl'}"
                    )

    # Nmap is optional
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
        "[run] nmap (service enumeration) "
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

        nmap_result = parse_nmap_xml(xml_text)

        typer.echo(
            f"[ok] {ip} services: "
            f"{len(nmap_result.services)}"
        )

        for service in nmap_result.services[:10]:
            name = service.service or "unknown"

            typer.echo(
                f" - {service.ip}:{service.port}/"
                f"{service.protocol} {name}"
            )
