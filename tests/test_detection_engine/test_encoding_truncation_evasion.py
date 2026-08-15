import base64
import gzip
from collections.abc import Iterator
from typing import cast

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_MARKER = "1' UNION SELECT username, password FROM users--"
_BLIND_MARKER = "1' OR '1'='1"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> Iterator[None]:
    sus_patterns_handler.configure(SecurityConfig())
    yield


def _json_body_request(payload: str) -> MockGuardRequest:
    body = f'{{"q": "{payload}"}}'.encode()
    return MockGuardRequest(
        method="POST",
        headers={"content-length": str(len(body)), "content-type": "application/json"},
        body_content=body,
    )


async def _is_threat(payload: str) -> bool:
    request = _json_body_request(payload)
    result = await detect_penetration_attempt(
        cast(GuardRequest, request), SecurityConfig()
    )
    return result.is_threat


async def test_baseline_marker_is_detected_unwrapped() -> None:
    assert await _is_threat(_MARKER) is True


async def test_base64_mime_whitespace_wrapped_marker_is_detected() -> None:
    single_b64 = base64.b64encode(_MARKER.encode()).decode()
    wrapped = "\n".join(single_b64[i : i + 20] for i in range(0, len(single_b64), 20))

    assert await _is_threat(wrapped) is True


async def test_base64_crlf_wrapped_marker_is_detected() -> None:
    single_b64 = base64.b64encode(_MARKER.encode()).decode()
    wrapped = "\r\n".join(single_b64[i : i + 20] for i in range(0, len(single_b64), 20))

    assert await _is_threat(wrapped) is True


async def test_gzip_then_base64_marker_is_detected() -> None:
    gz_b64 = base64.b64encode(gzip.compress(_MARKER.encode())).decode()

    assert await _is_threat(gz_b64) is True


async def test_double_base64_depth_2_marker_is_detected() -> None:
    depth_2 = base64.b64encode(base64.b64encode(_MARKER.encode())).decode()

    assert await _is_threat(depth_2) is True


async def test_double_base64_depth_8_marker_is_detected() -> None:
    content = _MARKER.encode()
    for _ in range(8):
        content = base64.b64encode(content)

    assert await _is_threat(content.decode()) is True


async def test_truncation_front_placed_marker_is_detected() -> None:
    body = _BLIND_MARKER + " " + "B" * 20000

    assert await _is_threat(body) is True


async def test_truncation_back_placed_marker_is_detected() -> None:
    body = "A" * 20000 + " " + _BLIND_MARKER

    assert await _is_threat(body) is True


async def test_truncation_dead_center_placed_marker_is_detected() -> None:
    body = "A" * 100000 + " " + _BLIND_MARKER + " " + "B" * 100000

    assert await _is_threat(body) is True


async def test_malformed_content_length_still_scans_body_via_prefix_reader() -> None:
    class _BoundedBodyReaderRequest(MockGuardRequest):
        async def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body[:max_bytes]

    body = f'{{"q": "{_MARKER}"}}'.encode()
    request = _BoundedBodyReaderRequest(
        method="POST",
        headers={"content-length": "not-a-number", "content-type": "application/json"},
        body_content=body,
    )

    result = await detect_penetration_attempt(
        cast(GuardRequest, request), SecurityConfig()
    )

    assert result.is_threat is True


async def test_negative_content_length_still_scans_body_via_prefix_reader() -> None:
    class _BoundedBodyReaderRequest(MockGuardRequest):
        async def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body[:max_bytes]

    body = f'{{"q": "{_MARKER}"}}'.encode()
    request = _BoundedBodyReaderRequest(
        method="POST",
        headers={"content-length": "-1", "content-type": "application/json"},
        body_content=body,
    )

    result = await detect_penetration_attempt(
        cast(GuardRequest, request), SecurityConfig()
    )

    assert result.is_threat is True


async def test_oversized_valid_content_length_still_skips_body_scan() -> None:
    class _BoundedBodyReaderRequest(MockGuardRequest):
        async def read_body_prefix(self, max_bytes: int) -> bytes:
            return self._body[:max_bytes]

    body = f'{{"q": "{_MARKER}"}}'.encode()
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)
    request = _BoundedBodyReaderRequest(
        method="POST",
        headers={"content-length": "10000000", "content-type": "application/json"},
        body_content=body,
    )

    result = await detect_penetration_attempt(cast(GuardRequest, request), config)

    assert result.is_threat is False
