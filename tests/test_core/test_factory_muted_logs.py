import logging
from types import SimpleNamespace

from guard_core.core.checks import build_default_pipeline
from guard_core.models import SecurityConfig


def test_factory_propagates_muted_check_logs() -> None:
    mw = SimpleNamespace(
        config=SecurityConfig(muted_check_logs={"rate_limit"}),
        logger=logging.getLogger("t"),
    )
    pipe = build_default_pipeline(mw)
    assert pipe.muted_check_logs == {"rate_limit"}
