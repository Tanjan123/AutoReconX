from autoreconx.stages.discovery import (
    run_dns_resolution,
    run_subfinder,
)


def test_run_subfinder_is_callable():
    assert callable(run_subfinder)

def test_run_dns_resolution_is_callable():
    assert callable(run_dns_resolution)
