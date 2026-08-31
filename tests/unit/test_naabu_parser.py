from autoreconx.modules.naabu import filter_ips, parse_naabu_output


def test_filter_ips_private_only():
    ips = ["10.0.0.1", "8.8.8.8", "172.16.0.5"]
    out = filter_ips(ips, allow_public=False)
    assert "10.0.0.1" in out
    assert "172.16.0.5" in out
    assert "8.8.8.8" not in out


def test_parse_naabu_json_lines():
    sample = """
{"ip":"10.0.0.1","port":80,"protocol":"tcp"}
{"host":"10.0.0.1","port":443,"protocol":"tcp"}
"""
    res = parse_naabu_output(sample)
    assert len(res.open_ports) == 2
    assert any(p.ip == "10.0.0.1" and p.port == 80 for p in res.open_ports)
