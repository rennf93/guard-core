from collections.abc import AsyncGenerator
from typing import Any

import pytest

from guard_core.decorators.base import RouteConfig
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


class _FakeRequest:
    def __init__(
        self,
        query_params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body_bytes: bytes = b"",
        url_path: str = "/",
        method: str = "GET",
        client_host: str = "127.0.0.1",
    ) -> None:
        self.query_params = query_params or {}
        self.headers = headers or {}
        self._body_bytes = body_bytes
        self.url_path = url_path
        self.method = method
        self.client_host = client_host
        self.state: Any = type("S", (), {})()

    async def body(self) -> bytes:
        return self._body_bytes


async def test_excluded_header_suppresses_match() -> None:
    config = SecurityConfig(excluded_detection_headers={"x-raw"})
    request = _FakeRequest(headers={"x-raw": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


async def test_excluded_param_suppresses_match() -> None:
    config = SecurityConfig(excluded_detection_params={"search"})
    request = _FakeRequest(query_params={"search": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


async def test_excluded_body_field_suppresses_match() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(body_bytes=b'{"notes": "<script>alert(1)</script>"}')
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


async def test_disabled_category_suppresses_match() -> None:
    config = SecurityConfig(enabled_detection_categories={"sqli"})
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


async def test_enabled_category_still_matches() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss"})
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Query param 'q'" in trigger


async def test_route_exclusion_adds_to_global_header_exclusions() -> None:
    config = SecurityConfig()
    route_config = RouteConfig()
    route_config.excluded_detection_headers = {"x-raw"}
    request = _FakeRequest(headers={"x-raw": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is False


async def test_route_params_override_global_params() -> None:
    config = SecurityConfig(excluded_detection_params={"global_only"})
    route_config = RouteConfig()
    route_config.excluded_detection_params = {"route_only"}
    request = _FakeRequest(query_params={"global_only": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is True


async def test_route_categories_override_global_categories() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss", "sqli"})
    route_config = RouteConfig()
    route_config.enabled_detection_categories = {"sqli"}
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is False


async def test_route_config_none_fields_inherit_from_config() -> None:
    config = SecurityConfig(excluded_detection_params={"inherit_me"})
    route_config = RouteConfig()
    request = _FakeRequest(query_params={"inherit_me": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is False


async def test_no_config_preserves_legacy_behaviour() -> None:
    request = _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request)
    detected = _result.is_threat
    assert detected is True


async def test_route_body_fields_override_global() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    route_config = RouteConfig()
    route_config.excluded_detection_body_fields = {"comments"}
    request = _FakeRequest(body_bytes=b'{"notes": "<script>alert(1)</script>"}')
    _result = await detect_penetration_attempt(request, config, route_config)
    detected = _result.is_threat
    assert detected is True


async def test_url_path_uses_enabled_categories() -> None:
    config = SecurityConfig(enabled_detection_categories={"xss"})
    request = _FakeRequest(url_path="/.git/index")
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is False


async def test_request_body_non_json_falls_back_to_full_scan() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(body_bytes=b"<script>alert(1)</script>")
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is True


async def test_request_body_invalid_json_with_excluded_body_fields() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    request = _FakeRequest(body_bytes=b"not valid json <script>alert(1)</script>")
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    assert detected is True


async def test_request_body_decode_failure_returns_false() -> None:
    class BadBodyRequest(_FakeRequest):
        async def body(self) -> bytes:
            raise RuntimeError("body read failed")

    request = BadBodyRequest(query_params={"q": "safe"})
    _result = await detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is False
    assert trigger == ""


async def test_request_body_field_threat_returns_field_message() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"safe"})
    request = _FakeRequest(body_bytes=b'{"q": "<script>alert(1)</script>"}')
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Request body field 'q'" in trigger


async def test_url_path_threat_message() -> None:
    request = _FakeRequest(url_path="/.git/index")
    _result = await detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "URL path" in trigger


async def test_header_threat_message() -> None:
    request = _FakeRequest(headers={"x-attack": "<script>alert(1)</script>"})
    _result = await detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Header 'x-attack'" in trigger


async def test_request_body_no_excluded_fields_still_scans_full_body() -> None:
    request = _FakeRequest(body_bytes=b"<script>alert(1)</script>")
    _result = await detect_penetration_attempt(request)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Request body" in trigger


async def test_unknown_client_host_is_handled() -> None:
    request = _FakeRequest(client_host="")
    request.client_host = ""
    _result = await detect_penetration_attempt(request)
    detected = _result.is_threat
    assert detected is False


async def test_body_loop_iterates_past_safe_field_to_detect_threat() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"placeholder"})
    body = b'{"safe": "harmless", "evil": "<script>alert(1)</script>"}'
    request = _FakeRequest(body_bytes=body)
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "Request body field 'evil'" in trigger


async def test_excluded_body_field_with_other_threat_field_still_detects() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"notes"})
    body = (
        b'{"notes": "<script>alert(1)</script>", "other": "<script>alert(2)</script>"}'
    )
    request = _FakeRequest(body_bytes=body)
    _result = await detect_penetration_attempt(request, config)
    detected = _result.is_threat
    trigger = _result.trigger_info
    assert detected is True
    assert "other" in trigger
