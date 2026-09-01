import typer
from . import __version__
from autoreconx.core.scope import parse_scope
from pathlib import Path
from datetime import datetime

from autoreconx.core.runner import CommandRunner
from autoreconx.modules.subfinder import build_subfinder_args, parse_subfinder_stdout
from autoreconx.core.scope import TargetKind
from autoreconx.modules.dnsx import build_dnsx_args, parse_dnsx_output, write_lines
from autoreconx.modules.naabu import build_naabu_args, filter_ips, parse_naabu_output
from autoreconx.modules.nmap import build_nmap_args, parse_nmap_xml
from urllib.parse import urlparse
from autoreconx.modules.httpx_toolkit import build_httpx_toolkit_args, parse_httpx_output, build_web_urls

app = typer.Typer(
    name="autoreconx",
    help="AutoReconX — authorized reconnaissance & attack-surface mapping framework (V1: skeleton).",
    add_completion=False,
)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Authorized target (domain/IP/CIDR within scope)."),
    ports: bool = typer.Option(False, help="Enable port discovery using naabu (active scan)."),
    allow_public: bool = typer.Option(
        False,
        help="Allow scanning public IPs (DANGEROUS). Enable only if explicitly authorized.",
    ),
    services: bool = typer.Option(False, help="Enable Nmap service enumeration on discovered open ports."),
    web: bool = typer.Option(False, help="Enable HTTP probing using ProjectDiscovery httpx-toolkit."),
) -> None:

    """
    Pipeline (current):
    scope -> subfinder -> dnsx -> (optional naabu) -> (optional nmap)
    """
    requested_path = "/"
    if "://" in target:
        u = urlparse(target)
        requested_path = u.path or "/"
        if u.query:
            requested_path = requested_path + "?" + u.query

    # 1) Scope validation (safety gate)
    try:
        scope = parse_scope(target)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    typer.echo(f"[scope OK] kind={scope.kind} target={scope.target}")

    # Create workspace for ALL scan types (domain/ip/cidr)
    scan_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    workspace = Path("workspaces") / scan_id
    raw_dir = workspace / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # Central runner for ALL stages
    runner = CommandRunner(default_timeout=120)

    # --- IP MODE (local/lab target) ---
    if scope.kind == TargetKind.IP:

        # For global public IPs, require explicit permission flag
        # (local/private/loopback are allowed by default)
        scan_ips = filter_ips([scope.target], allow_public=allow_public)
        if not scan_ips:
            typer.echo("[warn] target IP is public/global and scanning is disabled by default.")
            typer.echo("[hint] use --allow-public only if you are explicitly authorized.")
            return

        if not ports:
            typer.echo("[info] IP target detected. Use --ports to run naabu, and --services for nmap.")
            return

        typer.echo(f"[run] naabu (port discovery) targets=1 allow_public={allow_public}")

        ips_file = raw_dir / "ips.txt"
        write_lines(str(ips_file), scan_ips)

        naabu_args = build_naabu_args(str(ips_file), top_ports=1000, rate=200)
        naabu_res = runner.run(
            naabu_args,
            timeout=600,
            stdout_path=str(raw_dir / "naabu.jsonl"),
            stderr_path=str(raw_dir / "naabu.err"),
        )

        if naabu_res.timed_out:
            typer.echo("[warn] naabu timed out")
            return
        if naabu_res.returncode != 0:
            typer.echo(f"[warn] naabu failed (rc={naabu_res.returncode})")
            if naabu_res.stderr.strip():
                typer.echo(naabu_res.stderr.strip()[:500])
            return

        open_ports = parse_naabu_output(naabu_res.stdout)
        typer.echo(f"[ok] open ports found: {len(open_ports.open_ports)}")

        for p in open_ports.open_ports[:10]:
            typer.echo(f" - {p.ip}:{p.port}")

        # HTTPX Toolkit stage for IP/local lab targets
        if web:
            web_ports = {80, 443, 3000, 5000, 8000, 8080, 8443}
            urls: list[str] = []

            for p in open_ports.open_ports:
                if p.port not in web_ports:
                    continue

                scheme = "https" if p.port in {443, 8443} else "http"

                # Standard ports do not need :80 or :443.
                if (
                    (scheme == "http" and p.port == 80)
                    or (scheme == "https" and p.port == 443)
                ):
                    base = f"{scheme}://{p.ip}"
                else:
                    base = f"{scheme}://{p.ip}:{p.port}"

                urls.append(base + requested_path)

            if not urls:
                typer.echo(
                    "[info] no known web ports found to probe with httpx-toolkit."
                )
            else:
                urls_file = raw_dir / "urls.txt"
                write_lines(str(urls_file), urls)

                typer.echo(
                    f"[run] httpx-toolkit (HTTP probing) urls={len(urls)}"
                )

                httpx_args = build_httpx_toolkit_args(str(urls_file))

                try:
                    httpx_res = runner.run(
                        httpx_args,
                        timeout=300,
                        stdout_path=str(raw_dir / "httpx.jsonl"),
                        stderr_path=str(raw_dir / "httpx.err"),
                    )
                except FileNotFoundError as e:
                    typer.echo(f"[warn] {e}")
                    typer.echo(
                        "[hint] install ProjectDiscovery httpx-toolkit and ensure it is in PATH"
                    )
                else:
                    if httpx_res.timed_out:
                        typer.echo("[warn] httpx-toolkit timed out")

                    elif httpx_res.returncode != 0:
                        typer.echo(
                            f"[warn] httpx-toolkit failed "
                            f"(rc={httpx_res.returncode})"
                        )

                        if httpx_res.stderr.strip():
                            typer.echo(httpx_res.stderr.strip()[:500])

                    else:
                        parsed_http = parse_httpx_output(httpx_res.stdout)

                        typer.echo(
                            f"[ok] httpx results: {len(parsed_http.items)}"
                        )

                        for item in parsed_http.items[:10]:
                            title = item.title or ""
                            server = item.webserver or ""

                            typer.echo(
                                f" - {item.url} "
                                f"[{item.status_code}] "
                                f"{title} "
                                f"{server}".rstrip()
                            )

                            if item.tech:
                                typer.echo(
                                    f"   tech: {', '.join(item.tech)}"
                                )

                        typer.echo(
                            f"[saved] httpx raw output: "
                            f"{raw_dir / 'httpx.jsonl'}"
                        )

        # Nmap service enumeration
        if not services:
            typer.echo(
                "[info] service enumeration disabled "
                "(use --services to enable nmap stage)."
            )
            return

        ports_by_ip: dict[str, list[int]] = {}
        for op in open_ports.open_ports:
            ports_by_ip.setdefault(op.ip, []).append(op.port)

        typer.echo(f"[run] nmap (service enumeration) hosts={len(ports_by_ip)}")
        for ip, port_list in ports_by_ip.items():
            typer.echo(f"[run] nmap {ip} ports={sorted(set(port_list))}")

            xml_path = raw_dir / f"nmap-{ip}.xml"
            nmap_args = build_nmap_args(ip, port_list, xml_out=str(xml_path))
            nmap_res = runner.run(
                nmap_args,
                timeout=900,
                stdout_path=str(raw_dir / f"nmap-{ip}.stdout"),
                stderr_path=str(raw_dir / f"nmap-{ip}.err"),
            )

            if nmap_res.timed_out:
                typer.echo(f"[warn] nmap timed out for {ip}")
                continue
            if nmap_res.returncode != 0:
                typer.echo(f"[warn] nmap failed for {ip} (rc={nmap_res.returncode})")
                continue

            xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
            nmap_parsed = parse_nmap_xml(xml_text)

            typer.echo(f"[ok] {ip} services(open-only): {len(nmap_parsed.services)}")
            for s in nmap_parsed.services[:10]:
                name = s.service or "unknown"
                typer.echo(f" - {s.ip}:{s.port}/{s.protocol} {name}")

        return

    # 2) V1: run subfinder only for domain targets
    if scope.kind != TargetKind.DOMAIN:
        typer.echo("[info] Subfinder runs only for domain targets in V1.")
        return

    args = build_subfinder_args(scope.target)

    typer.echo("[run] subfinder (passive subdomain discovery)")
    result = runner.run(
        args,
        stdout_path=str(raw_dir / "subfinder.txt"),
        stderr_path=str(raw_dir / "subfinder.err"),
    )

    # 5) Handle failure states safely
    if result.timed_out:
        typer.echo("[warn] subfinder timed out")
        typer.echo(f"[saved] stderr: {raw_dir / 'subfinder.err'}")
        return

    if result.returncode != 0:
        typer.echo(f"[warn] subfinder failed (rc={result.returncode})")
        if result.stderr.strip():
            typer.echo(result.stderr.strip()[:500])
        typer.echo(f"[saved] stderr: {raw_dir / 'subfinder.err'}")
        return

    # 6) Parse + show summary
    parsed = parse_subfinder_stdout(result.stdout, root_domain=scope.target)

    typer.echo(f"[ok] subdomains discovered: {len(parsed.subdomains)}")
    for s in parsed.subdomains[:10]:
        typer.echo(f" - {s}")

    typer.echo(f"[saved] raw output: {raw_dir / 'subfinder.txt'}")

    # 7) dnsx stage (DNS resolution)
    typer.echo("[run] dnsx (DNS resolution)")

    # write subdomains to file for dnsx input
    subdomains_file = raw_dir / "subdomains.txt"
    write_lines(str(subdomains_file), parsed.subdomains)

    dnsx_args = build_dnsx_args(str(subdomains_file))

    try:
        dnsx_res = runner.run(
            dnsx_args,
            timeout=600,  # dns resolution can take longer; keep a hard cap
            stdout_path=str(raw_dir / "dnsx.jsonl"),
            stderr_path=str(raw_dir / "dnsx.err"),
        )
    except FileNotFoundError as e:
        typer.echo(f"[warn] {e}")
        typer.echo("[hint] install dnsx and ensure it is in PATH")
        return

    if dnsx_res.timed_out:
        typer.echo("[warn] dnsx timed out")
        typer.echo(f"[saved] raw dnsx stderr: {raw_dir / 'dnsx.err'}")
        return

    if dnsx_res.returncode != 0:
        typer.echo(f"[warn] dnsx failed (rc={dnsx_res.returncode})")
        if dnsx_res.stderr.strip():
            typer.echo(dnsx_res.stderr.strip()[:500])
        typer.echo(f"[saved] raw dnsx stderr: {raw_dir / 'dnsx.err'}")
        return

    resolved = parse_dnsx_output(dnsx_res.stdout, root_domain=scope.target)
    typer.echo(f"[ok] resolved hosts: {len(resolved.resolved)}")
    for item in resolved.resolved[:10]:
        typer.echo(f" - {item.host} -> {', '.join(item.ips)}")

    typer.echo(f"[saved] dnsx raw output: {raw_dir / 'dnsx.jsonl'}")

    # 8) HTTPX hostname probing (domain mode)
    host_seed_urls: list[str] = []

    if web:
        seed_urls: set[str] = set()

        for host_resolution in resolved.resolved:
            seed_urls.add(f"http://{host_resolution.host}")
            seed_urls.add(f"https://{host_resolution.host}")

        host_seed_urls = sorted(seed_urls)

        if not host_seed_urls:
            typer.echo("[info] no resolved hostnames available for HTTP probing.")
        else:
            urls_file = raw_dir / "urls-hosts.txt"
            write_lines(str(urls_file), host_seed_urls)

            typer.echo(
                f"[run] httpx-toolkit (HTTP probing - hostnames) "
                f"urls={len(host_seed_urls)}"
            )

            httpx_args = build_httpx_toolkit_args(str(urls_file))

            try:
                httpx_res = runner.run(
                    httpx_args,
                    timeout=300,
                    stdout_path=str(raw_dir / "httpx-hosts.jsonl"),
                    stderr_path=str(raw_dir / "httpx-hosts.err"),
                )
            except FileNotFoundError as e:
                typer.echo(f"[warn] {e}")
                typer.echo(
                    "[hint] install ProjectDiscovery httpx-toolkit "
                    "and ensure it is in PATH"
                )
            else:
                if httpx_res.timed_out:
                    typer.echo("[warn] httpx-toolkit timed out (hostnames)")

                elif httpx_res.returncode != 0:
                    typer.echo(
                        f"[warn] httpx-toolkit failed (hostnames) "
                        f"rc={httpx_res.returncode}"
                    )

                    if httpx_res.stderr.strip():
                        typer.echo(httpx_res.stderr.strip()[:500])

                else:
                    parsed_http = parse_httpx_output(httpx_res.stdout)

                    typer.echo(
                        f"[ok] httpx results (hostnames): "
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
                                f"   tech: {', '.join(item.tech)}"
                            )

                    typer.echo(
                        f"[saved] httpx raw output: "
                        f"{raw_dir / 'httpx-hosts.jsonl'}"
                    )


    # 9) naabu stage (port discovery) - optional
    if not ports:
        typer.echo("[info] port discovery disabled (use --ports to enable naabu stage).")
        return

    # Collect IPs from dnsx resolved results
    all_ips: list[str] = []
    for hr in resolved.resolved:
        all_ips.extend(list(hr.ips))

    # Safety: default is private IPs only unless allow_public=True
    scan_ips = filter_ips(all_ips, allow_public=allow_public)

    if not scan_ips:
        typer.echo("[warn] no IPs eligible for scanning (private-only by default).")
        typer.echo("[hint] use --allow-public only if you are explicitly authorized to scan those public IPs.")
        return

    typer.echo(f"[run] naabu (port discovery) targets={len(scan_ips)} allow_public={allow_public}")

    ips_file = raw_dir / "ips.txt"
    write_lines(str(ips_file), scan_ips)

    naabu_args = build_naabu_args(str(ips_file), top_ports=1000, rate=200)

    try:
        naabu_res = runner.run(
            naabu_args,
            timeout=600,
            stdout_path=str(raw_dir / "naabu.jsonl"),
            stderr_path=str(raw_dir / "naabu.err"),
        )
    except FileNotFoundError as e:
        typer.echo(f"[warn] {e}")
        typer.echo("[hint] install naabu and ensure it is in PATH")
        return

    if naabu_res.timed_out:
        typer.echo("[warn] naabu timed out")
        typer.echo(f"[saved] raw naabu stderr: {raw_dir / 'naabu.err'}")
        return

    if naabu_res.returncode != 0:
        typer.echo(f"[warn] naabu failed (rc={naabu_res.returncode})")
        if naabu_res.stderr.strip():
            typer.echo(naabu_res.stderr.strip()[:500])
        typer.echo(f"[saved] raw naabu stderr: {raw_dir / 'naabu.err'}")
        return

    open_ports = parse_naabu_output(naabu_res.stdout)
    typer.echo(f"[ok] open ports found: {len(open_ports.open_ports)}")
    for p in open_ports.open_ports[:10]:
        typer.echo(f" - {p.ip}:{p.port}")

    typer.echo(f"[saved] naabu raw output: {raw_dir / 'naabu.jsonl'}")

    # 10) HTTPX probing for additional web ports discovered by Naabu
    if web:
        discovered_port_urls = set(
            build_web_urls(
                resolved.resolved,
                open_ports.open_ports,
            )
        )

        extra_urls = sorted(
            discovered_port_urls - set(host_seed_urls)
        )

        if not extra_urls:
            typer.echo(
                "[info] no additional web port URLs discovered."
            )
        else:
            urls_file = raw_dir / "urls-ports.txt"
            write_lines(str(urls_file), extra_urls)

            typer.echo(
                f"[run] httpx-toolkit "
                f"(HTTP probing - discovered ports) "
                f"urls={len(extra_urls)}"
            )

            httpx_args = build_httpx_toolkit_args(str(urls_file))

            try:
                httpx_res = runner.run(
                    httpx_args,
                    timeout=300,
                    stdout_path=str(raw_dir / "httpx-ports.jsonl"),
                    stderr_path=str(raw_dir / "httpx-ports.err"),
                )
            except FileNotFoundError as e:
                typer.echo(f"[warn] {e}")
            else:
                if httpx_res.timed_out:
                    typer.echo(
                        "[warn] httpx-toolkit timed out "
                        "(discovered ports)"
                    )

                elif httpx_res.returncode != 0:
                    typer.echo(
                        f"[warn] httpx-toolkit failed "
                        f"(discovered ports) "
                        f"rc={httpx_res.returncode}"
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
                        f"[ok] httpx results "
                        f"(discovered ports): "
                        f"{len(parsed_http.items)}"
                    )

                    for item in parsed_http.items[:10]:
                        title = item.title or ""

                        typer.echo(
                            f" - {item.url} "
                            f"[{item.status_code}] "
                            f"{title}".rstrip()
                        )

                    typer.echo(
                        f"[saved] httpx raw output: "
                        f"{raw_dir / 'httpx-ports.jsonl'}"
                    )


    # 11) nmap stage (service enumeration)
    if not services:
        typer.echo("[info] service enumeration disabled (use --services to enable nmap stage).")
        return

    # group ports by IP
    ports_by_ip: dict[str, list[int]] = {}
    for op in open_ports.open_ports:
        ports_by_ip.setdefault(op.ip, []).append(op.port)

    typer.echo(f"[run] nmap (service enumeration) hosts={len(ports_by_ip)}")

    for ip, port_list in ports_by_ip.items():
        typer.echo(f"[run] nmap {ip} ports={sorted(set(port_list))}")

        xml_path = raw_dir / f"nmap-{ip}.xml"
        nmap_args = build_nmap_args(ip, port_list, xml_out=str(xml_path))

        nmap_res = runner.run(
            nmap_args,
            timeout=900,
            stdout_path=str(raw_dir / f"nmap-{ip}.stdout"),
            stderr_path=str(raw_dir / f"nmap-{ip}.err"),
        )

        if nmap_res.timed_out:
            typer.echo(f"[warn] nmap timed out for {ip}")
            continue

        if nmap_res.returncode != 0:
            typer.echo(f"[warn] nmap failed for {ip} (rc={nmap_res.returncode})")
            continue

        # parse XML from file
        xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
        nmap_parsed = parse_nmap_xml(xml_text)

        typer.echo(f"[ok] {ip} services: {len(nmap_parsed.services)}")
        for s in nmap_parsed.services[:10]:
            name = s.service or "unknown"
            typer.echo(f" - {s.ip}:{s.port}/{s.protocol} {name}")


@app.command()
def version() -> None:
    """Print AutoReconX version."""
    typer.echo(__version__)

def main() -> None:
    app()

if __name__ == "__main__":
    main()

