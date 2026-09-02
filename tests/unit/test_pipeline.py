from autoreconx.core.pipeline import extract_requested_path


def test_extract_requested_path_from_url():
    assert (
        extract_requested_path("http://127.0.0.1/DVWA/index.php") == "/DVWA/index.php"
    )


def test_extract_requested_path_with_query():
    assert extract_requested_path("http://127.0.0.1/page.php?id=5") == "/page.php?id=5"


def test_extract_requested_path_from_plain_target():
    assert extract_requested_path("127.0.0.1") == "/"
