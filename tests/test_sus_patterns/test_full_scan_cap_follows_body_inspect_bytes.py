import time
from collections.abc import Iterator
from typing import cast

import coverage
import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_JAVA_DESERIALIZATION_MARKER = "rO0AB"
_RAISED_BODY_INSPECT_BYTES = 1_000_000
_BODY_SIZE = 600_000
_MID_BODY_OFFSET = 300_000
_CPU_TIME_CEILING_SECONDS = 20.0


def _cov_scale() -> float:
    return 1.0 + 1.0 * (coverage.Coverage.current() is not None)


def _body_with_marker_at(body_size: int, offset: int, marker: str) -> str:
    padded_marker = f" {marker} "
    body = "A" * body_size
    return body[:offset] + padded_marker + body[offset + len(padded_marker) :]


def _raw_body_request(payload: str) -> MockGuardRequest:
    body = payload.encode()
    return MockGuardRequest(
        method="POST",
        headers={"content-length": str(len(body))},
        body_content=body,
    )


async def _is_threat(payload: str, config: SecurityConfig) -> bool:
    request = _raw_body_request(payload)
    result = await detect_penetration_attempt(cast(GuardRequest, request), config)
    return result.is_threat


@pytest.fixture(autouse=True)
def _restore_default_singleton_after_test() -> Iterator[None]:
    yield
    sus_patterns_handler.configure(SecurityConfig())


async def test_default_config_mid_body_payload_past_262144_stays_undetected() -> None:
    config = SecurityConfig()
    sus_patterns_handler.configure(config)
    body = _body_with_marker_at(
        _BODY_SIZE, _MID_BODY_OFFSET, _JAVA_DESERIALIZATION_MARKER
    )

    assert await _is_threat(body, config) is False


async def test_default_config_short_body_marker_still_detected() -> None:
    config = SecurityConfig()
    sus_patterns_handler.configure(config)

    assert (
        await _is_threat(f"prefix {_JAVA_DESERIALIZATION_MARKER} suffix", config)
        is True
    )


async def test_raised_body_inspect_cap_detects_mid_body_payload_past_default_cap() -> (
    None
):
    config = SecurityConfig(detection_max_body_inspect_bytes=_RAISED_BODY_INSPECT_BYTES)
    sus_patterns_handler.configure(config)
    body = _body_with_marker_at(
        _BODY_SIZE, _MID_BODY_OFFSET, _JAVA_DESERIALIZATION_MARKER
    )

    assert await _is_threat(body, config) is True


async def test_raised_body_inspect_cap_full_scan_of_no_hit_body_stays_bounded() -> None:
    config = SecurityConfig(detection_max_body_inspect_bytes=_RAISED_BODY_INSPECT_BYTES)
    sus_patterns_handler.configure(config)
    body = "A" * _RAISED_BODY_INSPECT_BYTES

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        result = await _is_threat(body, config)
        samples.append(time.process_time() - start)

    elapsed = min(samples)
    assert result is False
    assert elapsed < _CPU_TIME_CEILING_SECONDS * _cov_scale(), (
        f"full scan of a {_RAISED_BODY_INSPECT_BYTES}-byte no-hit body regressed: "
        f"ceiling={_CPU_TIME_CEILING_SECONDS}s actual={elapsed:.3f}s"
    )
