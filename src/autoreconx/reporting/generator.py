from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from autoreconx.correlation import (
    CorrelatedScanResult,
)
from autoreconx.prioritization import PriorityItem


def _asset_sources(asset: object) -> list[str]:
    sources = getattr(
        asset,
        "sources",
        set(),
    )

    return sorted(sources)


def build_report_data(
    result: CorrelatedScanResult,
    priorities: tuple[PriorityItem, ...],
) -> dict[str, Any]:
    """Build the common report representation."""

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "summary": {
            "domains": len(result.domains),
            "ip_addresses": len(result.ips),
            "ports": len(result.ports),
            "services": len(result.services),
            "web_apps": len(result.web_assets),
            "endpoints": len(result.endpoints),
            "relationships": len(
                result.relationships
            ),
        },
        "domains": [
            {
                "hostname": asset.hostname,
                "sources": _asset_sources(asset),
            }
            for asset in result.domains.values()
        ],
        "ip_addresses": [
            {
                "address": asset.address,
                "sources": _asset_sources(asset),
            }
            for asset in result.ips.values()
        ],
        "ports": [
            {
                "ip": asset.ip,
                "port": asset.port,
                "protocol": asset.protocol,
                "sources": _asset_sources(asset),
            }
            for asset in result.ports.values()
        ],
        "services": [
            {
                "ip": asset.ip,
                "port": asset.port,
                "protocol": asset.protocol,
                "service": asset.service,
                "product": asset.product,
                "version": asset.version,
                "sources": _asset_sources(asset),
            }
            for asset in result.services.values()
        ],
        "web_apps": [
            {
                "url": asset.url,
                "status_code": asset.status_code,
                "title": asset.title,
                "webserver": asset.webserver,
                "technologies": sorted(
                    asset.technologies
                ),
                "sources": _asset_sources(asset),
            }
            for asset in result.web_assets.values()
        ],
        "endpoints": [
            {
                "url": asset.url,
                "method": asset.method,
                "host": asset.host,
                "path": asset.path,
                "sources": _asset_sources(asset),
            }
            for asset in result.endpoints.values()
        ],
        "relationships": [
            {
                "source_type": relationship.source_type,
                "source_id": relationship.source_id,
                "relationship": relationship.relationship.value,
                "target_type": relationship.target_type,
                "target_id": relationship.target_id,
                "evidence_source": relationship.evidence_source,
            }
            for relationship in result.relationships
        ],
        "priorities": [
            {
                "asset_type": item.asset_type,
                "asset_id": item.asset_id,
                "score": item.score,
                "level": item.level.value,
                "reasons": list(item.reasons),
            }
            for item in priorities
        ],
    }


def write_json_report(
    data: dict[str, Any],
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return output_path


def _html_list(items: list[str]) -> str:
    if not items:
        return "<p>None</p>"

    return (
        "<ul>"
        + "".join(
            f"<li>{html.escape(item)}</li>"
            for item in items
        )
        + "</ul>"
    )


def write_html_report(
    data: dict[str, Any],
    output_path: Path,
) -> Path:
    """Generate a simple standalone HTML V1 report."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary = data["summary"]

    priority_html = ""

    for item in data["priorities"][:20]:
        reasons = _html_list(
            item["reasons"]
        )

        priority_html += f"""
        <div class="card">
          <strong>{html.escape(item["level"].upper())}</strong>
          — Score {item["score"]}
          — {html.escape(item["asset_type"])}
          <br>
          <code>{html.escape(item["asset_id"])}</code>
          {reasons}
        </div>
        """

    web_html = ""

    for item in data["web_apps"]:
        technologies = ", ".join(
            item["technologies"]
        )

        web_html += f"""
        <tr>
          <td>{html.escape(item["url"])}</td>
          <td>{item["status_code"] or ""}</td>
          <td>{html.escape(item["title"] or "")}</td>
          <td>{html.escape(item["webserver"] or "")}</td>
          <td>{html.escape(technologies)}</td>
        </tr>
        """

    endpoint_rows = ""

    # Limit huge crawl reports in HTML V1.
    for item in data["endpoints"][:500]:
        endpoint_rows += f"""
        <tr>
          <td>{html.escape(item["method"])}</td>
          <td>{html.escape(item["url"])}</td>
        </tr>
        """

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AutoReconX Report</title>
<style>
body {{
  font-family: Arial, sans-serif;
  margin: 40px;
  background: #0f172a;
  color: #e2e8f0;
}}
h1, h2 {{
  color: #38bdf8;
}}
.card {{
  background: #1e293b;
  padding: 14px;
  margin: 10px 0;
  border-radius: 8px;
}}
.grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
}}
table {{
  width: 100%;
  border-collapse: collapse;
}}
th, td {{
  border-bottom: 1px solid #334155;
  text-align: left;
  padding: 8px;
}}
code {{
  color: #fbbf24;
}}
</style>
</head>
<body>

<h1>AutoReconX Reconnaissance Report</h1>

<p><strong>Target:</strong> {html.escape(data["target"])}</p>
<p><strong>Scan ID:</strong> {html.escape(data["scan_id"])}</p>

<h2>Attack Surface Summary</h2>

<div class="grid">
<div class="card">Domains<br><strong>{summary["domains"]}</strong></div>
<div class="card">IPs<br><strong>{summary["ip_addresses"]}</strong></div>
<div class="card">Ports<br><strong>{summary["ports"]}</strong></div>
<div class="card">Services<br><strong>{summary["services"]}</strong></div>
<div class="card">Web Apps<br><strong>{summary["web_apps"]}</strong></div>
<div class="card">Endpoints<br><strong>{summary["endpoints"]}</strong></div>
<div class="card">Relationships<br><strong>{summary["relationships"]}</strong></div>
</div>

<h2>Priority Investigation Candidates</h2>
{priority_html or "<p>No priority indicators.</p>"}

<h2>Web Applications</h2>
<table>
<tr>
<th>URL</th>
<th>Status</th>
<th>Title</th>
<th>Server</th>
<th>Technologies</th>
</tr>
{web_html}
</table>

<h2>Endpoints</h2>
<p>Showing up to 500 discovered endpoints.</p>
<table>
<tr>
<th>Method</th>
<th>URL</th>
</tr>
{endpoint_rows}
</table>

</body>
</html>
"""

    output_path.write_text(
        document,
        encoding="utf-8",
    )

    return output_path


def generate_reports(
    result: CorrelatedScanResult,
    priorities: tuple[PriorityItem, ...],
    report_dir: Path,
) -> tuple[Path, Path]:
    """Generate JSON and HTML reports."""

    data = build_report_data(
        result,
        priorities,
    )

    json_path = write_json_report(
        data,
        report_dir / "report.json",
    )

    html_path = write_html_report(
        data,
        report_dir / "report.html",
    )

    return json_path, html_path
