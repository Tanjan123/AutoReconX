import pytest

from autoreconx.modules.katana import (
    build_katana_args,
    parse_katana_output,
)


def test_build_katana_args():
    args = build_katana_args(
        "urls.txt",
        depth=2,
    )

    assert args[0] == "katana"
    assert "-list" in args
    assert "urls.txt" in args
    assert "-jsonl" in args
    assert "-depth" in args
    assert "2" in args


def test_build_katana_args_rejects_invalid_depth():
    with pytest.raises(ValueError):
        build_katana_args(
            "urls.txt",
            depth=0,
        )


def test_parse_katana_request_endpoint():
    sample = """
{"request":{"method":"GET","endpoint":"http://127.0.0.1/DVWA/index.php"}}
{"request":{"method":"GET","endpoint":"http://127.0.0.1/DVWA/login.php"}}
"""

    result = parse_katana_output(sample)

    assert len(result.endpoints) == 2

    urls = {endpoint.url for endpoint in result.endpoints}

    assert "http://127.0.0.1/DVWA/index.php" in urls

    assert "http://127.0.0.1/DVWA/login.php" in urls


def test_parse_katana_deduplicates_urls():
    sample = """
{"request":{"method":"GET","endpoint":"https://example.com/login"}}
{"request":{"method":"GET","endpoint":"https://example.com/login"}}
"""

    result = parse_katana_output(sample)

    assert len(result.endpoints) == 1
