from autoreconx.modules.subfinder import parse_subfinder_stdout


def test_parse_subfinder_stdout_filters_and_normalizes():
    sample = """
api.example.com
DEV.EXAMPLE.COM
not-a-domain
a.evil.com
example.com
"""
    res = parse_subfinder_stdout(sample, root_domain="example.com")
    assert "api.example.com" in res.subdomains
    assert "dev.example.com" in res.subdomains
    assert "example.com" in res.subdomains
    assert "a.evil.com" not in res.subdomains
