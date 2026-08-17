import concurrent.futures
import json
import time

import pytest

from guard_core import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SecurityConfig()

_REDOS_PAYLOAD = "{{" * 10000
_BENIGN_MATCHING_PAYLOAD = "<script>alert(1)</script>"
_CONCURRENCY = 4
_DEADLINE_SECONDS = 30.0


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _json_body_request(payload: str) -> SyncMockGuardRequest:
    body = json.dumps({"outer": {"field": payload}}).encode()
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    return SyncMockGuardRequest(body_content=body, headers=headers)


def _raw_body_request(payload: str) -> SyncMockGuardRequest:
    body = payload.encode()
    headers = {"content-length": str(len(body))}
    return SyncMockGuardRequest(body_content=body, headers=headers)


def test_no_false_negative_under_concurrent_redos_sync() -> None:
    redos_request = _raw_body_request(_REDOS_PAYLOAD)
    benign_request = _raw_body_request(_BENIGN_MATCHING_PAYLOAD)

    def _detect(req: SyncMockGuardRequest) -> bool:
        result = detect_penetration_attempt(req, _CONFIG)
        return result.is_threat

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_CONCURRENCY + 1
    ) as executor:
        futures = []
        for _ in range(_CONCURRENCY):
            futures.append(executor.submit(_detect, redos_request))
        futures.append(executor.submit(_detect, benign_request))

        start = time.monotonic()
        results = [f.result(timeout=_DEADLINE_SECONDS) for f in futures]
        elapsed = time.monotonic() - start

    assert results[-1], (
        f"Benign matching payload was not detected under concurrent ReDoS load "
        f"(false negative). Elapsed: {elapsed:.2f}s"
    )
    assert elapsed < _DEADLINE_SECONDS, (
        f"Concurrent detect calls hung. Elapsed: {elapsed:.2f}s"
    )
