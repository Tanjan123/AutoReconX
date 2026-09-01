from autoreconx.models import DomainAsset, ScanResult
from autoreconx.reporting import print_scan_summary


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

    print_scan_summary(result)

    output = capsys.readouterr().out

    assert "normalized attack surface" in output
    assert "example.com" in output
    assert "domains:" in output
