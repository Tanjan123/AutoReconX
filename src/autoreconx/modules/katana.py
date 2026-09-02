from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class KatanaEndpoint:
    url: str
    method: str = "GET"
    host: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class KatanaResult:
    endpoints: tuple[KatanaEndpoint, ...]


def build_katana_args(
    input_file: str,
    *,
    depth: int = 2,
) -> list[str]:
    """
    Build conservative Katana arguments for V1.

    -list: read authorized seed URLs from file
    -depth: limit crawl depth
    -jsonl: structured output
    -silent: reduce console noise
    -omit-raw: do not store raw request/response in JSONL
    -omit-body: do not store response bodies in JSONL
    """

    if depth < 1:
        raise ValueError("Katana depth must be at least 1")

    return [
        "katana",
        "-list",
        input_file,
        "-depth",
        str(depth),
        "-jsonl",
        "-silent",
        "-omit-raw",
        "-omit-body",
    ]


def parse_katana_output(output: str) -> KatanaResult:
    """
    Parse Katana JSONL output into normalized endpoints.

    Katana output can vary slightly between versions, so extraction
    is deliberately tolerant of several common field locations.
    """

    endpoints: dict[str, KatanaEndpoint] = {}

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(obj, dict):
            continue

        url = None
        method = "GET"

        # Common Katana JSONL format.
        request = obj.get("request")

        if isinstance(request, dict):
            candidate = request.get("endpoint") or request.get("url")

            if isinstance(candidate, str):
                url = candidate.strip()

            request_method = request.get("method")

            if isinstance(request_method, str) and request_method.strip():
                method = request_method.strip().upper()

        # Tolerate top-level output fields as well.
        if not url:
            candidate = obj.get("url") or obj.get("endpoint")

            if isinstance(candidate, str):
                url = candidate.strip()

        if not url:
            continue

        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            continue

        if not parsed.hostname:
            continue

        normalized_url = url.strip()

        endpoints[normalized_url] = KatanaEndpoint(
            url=normalized_url,
            method=method,
            host=parsed.hostname.lower(),
            path=parsed.path or "/",
        )

    return KatanaResult(endpoints=tuple(endpoints[url] for url in sorted(endpoints)))
