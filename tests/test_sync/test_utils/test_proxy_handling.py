import logging
from unittest.mock import patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest


def test_extract_client_ip_without_trusted_proxies() -> None:
    config = SecurityConfig()

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_with_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_with_cidr_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.0/8"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "1.2.3.4"


def test_extract_client_ip_with_proxy_depth() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "5.6.7.8"


def test_extract_client_ip_without_xforwarded() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_with_untrusted_proxy() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_error_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "invalid-ip"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        with patch(
            "guard_core.sync.utils.ip_address", side_effect=ValueError("Invalid IP")
        ):
            ip = extract_client_ip(request, config)
            assert ip == "127.0.0.1"
            assert "Potential IP spoof attempt" in caplog.text


def test_extract_client_ip_no_client() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host=None,
    )

    ip = extract_client_ip(request, config)
    assert ip == "unknown"


def test_extract_client_ip_fallback_to_connecting_ip() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"


def test_extract_client_ip_untrusted_without_forwarded() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
    )

    ip = extract_client_ip(request, config)
    assert ip == "127.0.0.1"
