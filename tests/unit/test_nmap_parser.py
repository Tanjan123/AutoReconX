from autoreconx.modules.nmap import parse_nmap_xml


def test_parse_nmap_xml_basic():
    sample = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    res = parse_nmap_xml(sample)
    assert len(res.services) == 1
    s = res.services[0]
    assert s.ip == "10.0.0.1"
    assert s.port == 80
    assert s.service == "http"
