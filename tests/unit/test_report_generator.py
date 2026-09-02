import json
from pathlib import Path

from autoreconx.correlation import correlate_scan
from autoreconx.models import (
    DomainAsset,
    ScanResult,
    WebAsset,
)
from autoreconx.prioritization import (
    prioritize_scan,
)
from autoreconx.reporting import generate_reports


def test_generate_json_and_html_reports(
    tmp_path: Path,
):
    scan = ScanResult(
        scan_id="test-scan",
        target="example.com",
    )

    scan.domains.append(
        DomainAsset(
            hostname="example.com",
            source="target",
        )
    )

    scan.web_assets.append(
        WebAsset(
            url="https://example.com",
            status_code=200,
            title="Example",
            technologies=("nginx",),
            source="httpx",
        )
    )

    correlated = correlate_scan(scan)
    priorities = prioritize_scan(correlated)

    json_path, html_path = generate_reports(
        correlated,
        priorities,
        tmp_path,
    )

    assert json_path.exists()
    assert html_path.exists()

    data = json.loads(
        json_path.read_text(
            encoding="utf-8"
        )
    )

    assert data["target"] == "example.com"
    assert data["summary"]["domains"] == 1
    assert data["summary"]["web_apps"] == 1

    html_content = html_path.read_text(
        encoding="utf-8"
    )

    assert "AutoReconX" in html_content
    assert "example.com" in html_content
