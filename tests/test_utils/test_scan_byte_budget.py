import json
import logging

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_BUDGET_WARNING_TEXT = "detection_max_scan_bytes (1024) reached"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _json_body_request(payload: dict[str, str]) -> MockGuardRequest:
    body = json.dumps(payload).encode()
    return MockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


async def test_byte_budget_warning_fires_once_across_many_skipped_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(detection_max_scan_bytes=1024)
    payload = {f"k{i}": "x" * 200 for i in range(10)}
    request = _json_body_request(payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert caplog.text.count(_BUDGET_WARNING_TEXT) == 1


async def test_embedded_json_value_byte_budget_skips_remaining_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(detection_max_scan_bytes=1024)
    embedded = json.dumps({f"k{i}": "x" * 200 for i in range(10)})
    request = MockGuardRequest(query_params={"filters": embedded})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert caplog.text.count(_BUDGET_WARNING_TEXT) == 1
