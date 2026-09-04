import pytest

from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


def _manager() -> SusPatternsManager:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config
    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    manager = SusPatternsManager(SecurityConfig())
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config
    return manager


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "{{ format(x) }}",
        "{{ item.price | round(2) }}",
        "{{ cart.items.map(item => item.price) }}",
        "{{ 2024-01-02 }}",
        "#{2024-12-31}",
    ],
)
async def test_ordinary_template_filter_calls_and_dates_stay_benign(
    payload: str,
) -> None:
    manager = _manager()
    result = await manager.detect(
        content=payload, ip_address="198.51.100.4", context="request_body"
    )
    assert result["is_threat"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "{{config.items()}}",
        "#{T(java.lang.Runtime).exec('id')}",
        "{{7*7}}",
        "#{7*7}",
    ],
)
async def test_real_ssti_call_and_arithmetic_shapes_are_still_detected(
    payload: str,
) -> None:
    manager = _manager()
    result = await manager.detect(
        content=payload, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "template" for threat in result["threats"])
