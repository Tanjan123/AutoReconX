from autoreconx.stages.crawl import (
    _allowed_hosts,
    run_crawl,
)


def test_run_crawl_is_callable():
    assert callable(run_crawl)


def test_allowed_hosts():
    urls = (
        "https://example.com",
        "https://api.example.com/login",
    )

    hosts = _allowed_hosts(urls)

    assert hosts == {
        "example.com",
        "api.example.com",
    }
