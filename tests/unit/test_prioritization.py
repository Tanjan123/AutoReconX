from autoreconx.correlation import correlate_scan
from autoreconx.models import (
    DomainAsset,
    EndpointAsset,
    ScanResult,
    ServiceAsset,
    WebAsset,
)
from autoreconx.prioritization import (
    PriorityLevel,
    prioritize_scan,
)


def test_admin_domain_priority():
    scan = ScanResult(
        scan_id="test",
        target="example.com",
    )

    scan.domains.append(
        DomainAsset(
            hostname="admin.example.com",
            source="subfinder",
        )
    )

    result = prioritize_scan(correlate_scan(scan))

    assert len(result) == 1
    assert result[0].score == 30
    assert result[0].level == PriorityLevel.MEDIUM


def test_database_service_priority():
    scan = ScanResult(
        scan_id="test",
        target="127.0.0.1",
    )

    scan.services.append(
        ServiceAsset(
            ip="127.0.0.1",
            port=3306,
            protocol="tcp",
            service="mysql",
            source="nmap",
        )
    )

    result = prioritize_scan(correlate_scan(scan))

    assert result[0].score == 25


def test_interesting_endpoint_priority():
    scan = ScanResult(
        scan_id="test",
        target="example.com",
    )

    scan.endpoints.append(
        EndpointAsset(
            url="https://example.com/admin/login",
            path="/admin/login",
            source="katana",
        )
    )

    result = prioritize_scan(correlate_scan(scan))

    assert result[0].score == 40
    assert result[0].level == PriorityLevel.HIGH


def test_live_web_application_gets_low_priority():
    scan = ScanResult(
        scan_id="test",
        target="example.com",
    )

    scan.web_assets.append(
        WebAsset(
            url="https://example.com",
            status_code=200,
            source="httpx",
        )
    )

    result = prioritize_scan(correlate_scan(scan))

    assert result[0].score == 5
    assert result[0].level == PriorityLevel.LOW
