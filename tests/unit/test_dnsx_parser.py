from autoreconx.modules.dnsx import parse_dnsx_output


def test_parse_dnsx_json_lines():
    sample = """
{"host":"api.example.com","a":["1.1.1.1"]}
{"host":"dev.example.com","a":["2.2.2.2","2.2.2.3"]}
{"host":"evil.com","a":["9.9.9.9"]}
"""
    res = parse_dnsx_output(sample, root_domain="example.com")
    hosts = {h.host for h in res.resolved}
    assert "api.example.com" in hosts
    assert "dev.example.com" in hosts
    assert "evil.com" not in hosts


def test_parse_dnsx_plain_fallback():
    sample = """
api.example.com 1.1.1.1
dev.example.com [2.2.2.2]
"""
    res = parse_dnsx_output(sample, root_domain="example.com")
    assert any(h.host == "api.example.com" for h in res.resolved)
    assert any(h.host == "dev.example.com" for h in res.resolved)
