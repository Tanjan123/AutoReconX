from autoreconx.stages.ports import run_port_discovery


def test_run_port_discovery_is_callable():
    assert callable(run_port_discovery)
