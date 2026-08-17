import asyncio
import json
import time

import pytest

from guard_core import SecurityConfig
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_CONFIG = SecurityConfig()

_REDOS_PAYLOAD = "{{" * 10000
_BENIGN_MATCHING_PAYLOAD = "<script>alert(1)</script>"
_CONCURRENCY = 4
_DEADLINE_SECONDS = 30.0


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _json_body_request(payload: str) -> MockGuardRequest:
    body = json.dumps({"outer": {"field": payload}}).encode()
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    return MockGuardRequest(body_content=body, headers=headers)


async def test_no_false_negative_under_concurrent_redos_async() -> None:
    redos_request = _json_body_request(_REDOS_PAYLOAD)
    benign_request = _json_body_request(_BENIGN_MATCHING_PAYLOAD)

    tasks = []
    for _ in range(_CONCURRENCY):
        tasks.append(detect_penetration_attempt(redos_request, _CONFIG))
    tasks.append(detect_penetration_attempt(benign_request, _CONFIG))

    start = time.monotonic()
    results = await asyncio.gather(*tasks)
    elapsed = time.monotonic() - start

    assert results[-1].is_threat, (
        f"Benign matching payload was not detected under concurrent ReDoS load "
        f"(false negative). Elapsed: {elapsed:.2f}s"
    )
    assert elapsed < _DEADLINE_SECONDS, (
        f"Concurrent detect calls hung. Elapsed: {elapsed:.2f}s"
    )
