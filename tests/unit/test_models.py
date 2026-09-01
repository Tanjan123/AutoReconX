from autoreconx.models import (
    DomainAsset,
    EndpointAsset,
    IPAsset,
    PortAsset,
    ScanResult,
    ServiceAsset,
    WebAsset,
)


def test_create_normalized_assets():
    domain = DomainAsset(
        hostname="api.example.com",
        source="subfinder",
    )

    ip = IPAsset(
        address="10.0.0.1",
        source="dnsx",
    )

    port = PortAsset(
        ip="10.0.0.1",
        port=443,
        source="naabu",
    )

    service = ServiceAsset(
        ip="10.0.0.1",
        port=443,
        protocol="tcp",
        service="https",
        product="nginx",
        version="1.24.0",
        source="nmap",
    )

    web = WebAsset(
        url="https://api.example.com",
        status_code=200,
        title="API",
        technologies=("nginx",),
        source="httpx",
    )

    endpoint = EndpointAsset(
        url="https://api.example.com/login",
        path="/login",
        source="katana",
    )

    assert domain.hostname == "api.example.com"
    assert ip.address == "10.0.0.1"
    assert port.port == 443
    assert service.service == "https"
    assert web.status_code == 200
    assert endpoint.path == "/login"


def test_scan_result_collects_assets():
    result = ScanResult(
        scan_id="test-scan",
        target="example.com",
    )

    result.domains.append(
        DomainAsset(
            hostname="api.example.com",
            source="subfinder",
        )
    )

    result.ports.append(
        PortAsset(
            ip="10.0.0.1",
            port=443,
            source="naabu",
        )
    )

    assert len(result.domains) == 1
    assert len(result.ports) == 1
