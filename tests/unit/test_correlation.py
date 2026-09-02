from autoreconx.correlation import (
    RelationshipType,
    correlate_scan,
)
from autoreconx.models import (
    DNSResolution,
    DomainAsset,
    EndpointAsset,
    IPAsset,
    PortAsset,
    ScanResult,
    ServiceAsset,
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

def test_correlation_builds_ip_to_port_relationship():
    result = ScanResult(
        scan_id="test",
        target="10.0.0.1",
    )

    result.ips.append(
        IPAsset(
            address="10.0.0.1",
            source="target",
        )
    )

    result.ports.append(
        PortAsset(
            ip="10.0.0.1",
            port=80,
            source="naabu",
        )
    )

    correlated = correlate_scan(result)

    assert any(
        relationship.relationship
        == RelationshipType.EXPOSES
        and relationship.source_id
        == "10.0.0.1"
        and relationship.target_id
        == "10.0.0.1:80/tcp"
        for relationship in correlated.relationships
    )


def test_correlation_builds_port_to_service_relationship():
    result = ScanResult(
        scan_id="test",
        target="10.0.0.1",
    )

    result.ports.append(
        PortAsset(
            ip="10.0.0.1",
            port=80,
            source="naabu",
        )
    )

    result.services.append(
        ServiceAsset(
            ip="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            source="nmap",
        )
    )

    correlated = correlate_scan(result)

    assert any(
        relationship.relationship
        == RelationshipType.RUNS
        for relationship in correlated.relationships
    )


def test_correlation_builds_web_to_endpoint_relationship():
    result = ScanResult(
        scan_id="test",
        target="example.com",
    )

    result.web_assets.append(
        WebAsset(
            url="https://example.com",
            source="httpx",
        )
    )

    result.endpoints.append(
        EndpointAsset(
            url="https://example.com/login",
            method="GET",
            host="example.com",
            path="/login",
            source="katana",
        )
    )

    correlated = correlate_scan(result)

    assert any(
        relationship.relationship
        == RelationshipType.CONTAINS
        for relationship in correlated.relationships
    )

def test_correlation_builds_domain_to_ip_relationship():
    result = ScanResult(
        scan_id="test",
        target="example.com",
    )

    result.dns_resolutions.append(
        DNSResolution(
            hostname="api.example.com",
            address="10.0.0.1",
            source="dnsx",
        )
    )

    correlated = correlate_scan(result)

    assert any(
        relationship.relationship
        == RelationshipType.RESOLVES_TO
        and relationship.source_id
        == "api.example.com"
        and relationship.target_id
        == "10.0.0.1"
        and relationship.evidence_source
        == "dnsx"
        for relationship in correlated.relationships
    )
