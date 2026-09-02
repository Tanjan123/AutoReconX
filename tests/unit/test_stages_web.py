from autoreconx.modules.naabu import OpenPort
from autoreconx.stages.web import (
    build_ip_web_urls,
    run_http_probe,
)


def test_run_http_probe_is_callable():
    assert callable(run_http_probe)


def test_build_ip_web_urls():
    ports = (
        OpenPort(ip="127.0.0.1", port=80),
        OpenPort(ip="127.0.0.1", port=3306),
    )

    urls = build_ip_web_urls(
        "127.0.0.1",
        ports,
        requested_path="/DVWA/index.php",
    )

    assert "http://127.0.0.1/DVWA/index.php" in urls

    assert all(":3306" not in url for url in urls)
