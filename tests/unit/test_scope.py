import pytest

from autoreconx.core.scope import TargetKind, is_subdomain_of, parse_scope


def test_parse_domain_scope():
    s = parse_scope("example.com")
    assert s.kind == TargetKind.DOMAIN
    assert s.target == "example.com"
    assert s.allows_domain("api.example.com")
    assert not s.allows_domain("evil-example.com")


def test_parse_ip_scope():
    s = parse_scope("1.2.3.4")
    assert s.kind == TargetKind.IP
    assert s.allows_ip("1.2.3.4")
    assert not s.allows_ip("1.2.3.5")


def test_parse_cidr_scope():
    s = parse_scope("10.0.0.0/24")
    assert s.kind == TargetKind.CIDR
    assert s.allows_ip("10.0.0.1")
    assert not s.allows_ip("10.0.1.1")


def test_accept_url_input():
    s = parse_scope("https://example.com/login")
    assert s.kind == TargetKind.DOMAIN
    assert s.target == "example.com"


def test_invalid_target():
    with pytest.raises(ValueError):
        parse_scope("not a target")


def test_subdomain_check():
    assert is_subdomain_of("a.b.example.com", "example.com")
    assert is_subdomain_of("example.com", "example.com")
    assert not is_subdomain_of("example.com.evil.com", "example.com")
