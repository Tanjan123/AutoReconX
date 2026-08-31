from autoreconx.modules.httpx_toolkit import parse_httpx_output


def test_parse_httpx_json_lines():
    sample = """
{"url":"http://127.0.0.1/DVWA/index.php","status_code":200,"title":"Damn Vulnerable Web Application (DVWA)","webserver":"Apache","tech":["PHP","Apache"]}
"""
    res = parse_httpx_output(sample)
    assert len(res.items) == 1
    assert res.items[0].status_code == 200
    assert "DVWA" in (res.items[0].title or "")
