from autoreconx.stages.services import run_service_enumeration


def test_run_service_enumeration_is_callable():
    assert callable(run_service_enumeration)
