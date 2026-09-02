from autoreconx.core.profiles import (
    ScanProfile,
    get_profile_config,
)


def test_passive_profile():
    config = get_profile_config(ScanProfile.PASSIVE)

    assert config.dns is False
    assert config.ports is False
    assert config.web is False


def test_standard_profile():
    config = get_profile_config(ScanProfile.STANDARD)

    assert config.dns is True
    assert config.web is True
    assert config.ports is False


def test_full_profile():
    config = get_profile_config(ScanProfile.FULL)

    assert config.dns is True
    assert config.web is True
    assert config.ports is True
    assert config.services is True
    assert config.crawl is True
