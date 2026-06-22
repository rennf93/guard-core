from typing import cast

from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import detect_penetration_attempt

_SQLI_BODY = b'{"q": "1 OR 1=1 UNION SELECT password FROM users--"}'


class _BodyRequest:
    def __init__(self, body: bytes = b"", content_length: int | None = None) -> None:
        self._body = body
        self.query_params: dict[str, str] = {}
        self.headers: dict[str, str] = {}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        self.url_path = "/"
        self.method = "POST"
        self.client_host = "127.0.0.1"
        self.state = type("S", (), {})()
        self.body_read = False

    async def body(self) -> bytes:
        self.body_read = True
        return self._body


async def test_over_cap_body_is_not_read_or_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=10_000_000)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await detect_penetration_attempt(cast(GuardRequest, request), config)

    assert request.body_read is False
    assert result.is_threat is False


async def test_at_cap_body_is_still_read_and_scanned() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=1024)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await detect_penetration_attempt(cast(GuardRequest, request), config)

    assert request.body_read is True
    assert result.is_threat is True


async def test_missing_content_length_still_scans() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=None)
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await detect_penetration_attempt(cast(GuardRequest, request), config)

    assert request.body_read is True
    assert result.is_threat is True


async def test_malformed_content_length_falls_back_to_scanning() -> None:
    request = _BodyRequest(body=_SQLI_BODY, content_length=None)
    request.headers["content-length"] = "not-a-number"
    config = SecurityConfig(detection_max_body_inspect_bytes=1024)

    result = await detect_penetration_attempt(cast(GuardRequest, request), config)

    assert request.body_read is True
    assert result.is_threat is True
