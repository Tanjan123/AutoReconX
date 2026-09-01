from autoreconx.modules.dnsx import HostResolution
from autoreconx.modules.httpx_toolkit import build_web_urls, parse_httpx_output
from autoreconx.modules.naabu import OpenPort


def test_parse_httpx_json_lines():
    sample = """
{"url":"http://127.0.0.1/DVWA/index.php","status_code":200,"title":"Damn Vulnerable Web Application (DVWA)","webserver":"Apache","tech":["PHP","Apache"]}
"""
    res = parse_httpx_output(sample)
    assert len(res.items) == 1
    assert res.items[0].status_code == 200
    assert "DVWA" in (res.items[0].title or "")

def test_build_web_urls_correlates_hostname_and_port():
    resolved = (
        HostResolution(
            host="api.example.com",
            ips=("1.2.3.4",),
        ),
        HostResolution(
            host="admin.example.com",
            ips=("5.6.7.8",),
        ),
    )

    ports = (
        OpenPort(ip="1.2.3.4", port=443),
        OpenPort(ip="5.6.7.8", port=80),
        OpenPort(ip="5.6.7.8", port=22),
    )

    urls = build_web_urls(resolved, ports)

    assert "https://api.example.com" in urls
    assert "http://admin.example.com" in urls

    # SSH must not become a web URL.
    assert all(":22" not in url for url in urls)
