from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class HttpxItem:
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    tech: tuple[str, ...] = ()


@dataclass(frozen=True)
class HttpxResult:
    items: tuple[HttpxItem, ...]


def build_httpx_toolkit_args(input_file: str) -> list[str]:
    """
    Use the ProjectDiscovery binary name used by Kali: httpx-toolkit
    JSON output is easiest to parse and good for evidence.
    """
    return [
        "httpx-toolkit",
        "-silent",
        "-json",
        "-l",
        input_file,
        "-status-code",
        "-title",
        "-server",
        "-tech-detect",
        "-follow-redirects",
    ]


def parse_httpx_output(output: str) -> HttpxResult:
    items: list[HttpxItem] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if not (line.startswith("{") and line.endswith("}")):
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = obj.get("url") or obj.get("final_url")
        if not isinstance(url, str) or not url.strip():
            continue
        url = url.strip()

        status = obj.get("status_code")
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        if not isinstance(status, int):
            status = None

        title = obj.get("title")
        if not isinstance(title, str):
            title = None

        webserver = obj.get("webserver") or obj.get("server")
        if not isinstance(webserver, str):
            webserver = None

        tech_val = obj.get("tech")
        tech: tuple[str, ...] = ()
        if isinstance(tech_val, list):
            tech = tuple(sorted({t for t in tech_val if isinstance(t, str) and t.strip()}))

        items.append(
            HttpxItem(
                url=url,
                status_code=status,
                title=title.strip() if title else None,
                webserver=webserver.strip() if webserver else None,
                tech=tech,
            )
        )

    return HttpxResult(items=tuple(items))
