from autoreconx.modules.dnsx import HostResolution
from autoreconx.modules.httpx_toolkit import HttpxItem
from autoreconx.modules.katana import KatanaEndpoint
from autoreconx.modules.naabu import OpenPort
from autoreconx.modules.nmap import NmapService
from autoreconx.normalization import (
    normalize_endpoints,
    normalize_ports,
    normalize_resolutions,
    normalize_services,
    normalize_subdomains,
    normalize_web_assets,
)


def test_normalize_subdomains_deduplicates():
    result = normalize_subdomains(
        [
            "API.EXAMPLE.COM",
            "api.example.com",
            "dev.example.com.",
        ]
    )

    assert len(result) == 2
    assert result[0].hostname == "api.example.com"


def test_normalize_resolutions():
    result_domains, result_ips = normalize_resolutions(
        [
            HostResolution(
                host="api.example.com",
                ips=("10.0.0.1", "10.0.0.2"),
            )
        ]
    )

    assert len(result_domains) == 1
    assert len(result_ips) == 2
    assert result_ips[0].source == "dnsx"


def test_normalize_ports_deduplicates():
    result = normalize_ports(
        [
            OpenPort(ip="10.0.0.1", port=80),
            OpenPort(ip="10.0.0.1", port=80),
        ]
    )

    assert len(result) == 1
    assert result[0].port == 80


def test_normalize_services():
    result = normalize_services(
        [
            NmapService(
                ip="10.0.0.1",
                port=80,
                protocol="tcp",
                service="http",
                product="nginx",
                version="1.24.0",
            )
        ]
    )

    assert len(result) == 1
    assert result[0].service == "http"
    assert result[0].product == "nginx"


def test_normalize_web_assets_deduplicates():
    result = normalize_web_assets(
        [
            HttpxItem(
                url="https://example.com",
                status_code=200,
                title="Example",
            ),
            HttpxItem(
                url="https://example.com",
                status_code=200,
                title="Example",
            ),
        ]
    )

    assert len(result) == 1
    assert result[0].status_code == 200


def test_normalize_endpoints_deduplicates():
    result = normalize_endpoints(
        [
            KatanaEndpoint(
                url="https://example.com/login",
                method="GET",
                host="example.com",
                path="/login",
            ),
            KatanaEndpoint(
                url="https://example.com/login",
                method="GET",
                host="example.com",
                path="/login",
            ),
        ]
    )

    assert len(result) == 1
    assert result[0].path == "/login"
