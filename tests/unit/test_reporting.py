from autoreconx.correlation import correlate_scan
from autoreconx.models import DomainAsset, ScanResult
from autoreconx.prioritization import (
    PriorityItem,
    PriorityLevel,
)
from autoreconx.reporting import (
    print_priority_summary,
    print_scan_summary,
)


def test_print_scan_summary(capsys):
    result = ScanResult(
        scan_id="test",
        target="example.com",
    )

    result.domains.append(
        DomainAsset(
            hostname="api.example.com",
            source="subfinder",
        )
    )

    correlated = correlate_scan(result)
    print_scan_summary(correlated)
    output = capsys.readouterr().out

    assert "correlated attack surface" in output
    assert "example.com" in output
    assert "domains:" in output


def test_print_priority_summary(capsys):
    items = (
        PriorityItem(
            asset_type="endpoint",
            asset_id="https://example.com/admin/login",
            score=40,
            level=PriorityLevel.HIGH,
            reasons=(
                "Interesting path indicator: admin",
                "Interesting path indicator: login",
            ),
        ),
    )

    print_priority_summary(items)

    output = capsys.readouterr().out

    assert "top investigation candidates" in output
    assert "HIGH" in output
    assert "admin/login" in output
