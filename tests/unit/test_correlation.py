from autoreconx.correlation import correlate_scan
from autoreconx.models import (
    DomainAsset,
    PortAsset,
    ScanResult,
    WebAsset,
)


def test_correlation_deduplicates_domains_and_preserves_sources():
    result = ScanResult(
        scan_id="test",
        target="example.com",
    )

    result.domains.extend(
        [
            DomainAsset(
                hostname="api.example.com",
                source="subfinder",
            ),
            DomainAsset(
                hostname="api.example.com",
                source="dnsx",
            ),
        ]
    )

    correlated = correlate_scan(result)

    assert len(correlated.domains) == 1

    domain = correlated.domains[
        "api.example.com"
    ]

    assert domain.sources == {
        "subfinder",
        "dnsx",
    }


def test_correlation_deduplicates_ports():
    result = ScanResult(
        scan_id="test",
        target="example.com",
    )

    result.ports.extend(
        [
            PortAsset(
                ip="10.0.0.1",
                port=443,
                source="naabu",
            ),
            PortAsset(
                ip="10.0.0.1",
                port=443,
                source="naabu",
            ),
        ]
    )

    correlated = correlate_scan(result)

    assert len(correlated.ports) == 1


def test_correlation_merges_web_technologies():
    result = ScanResult(
        scan_id="test",
        target="example.com",
    )

    result.web_assets.extend(
        [
            WebAsset(
                url="https://example.com",
                technologies=("nginx",),
                source="httpx",
            ),
            WebAsset(
                url="https://example.com",
                technologies=("PHP",),
                source="httpx",
            ),
        ]
    )

    correlated = correlate_scan(result)

    web = correlated.web_assets[
        "https://example.com"
    ]

    assert web.technologies == {
        "nginx",
        "PHP",
    }
