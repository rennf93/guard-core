import logging
from unittest.mock import patch

import pytest

from guard_core._utils import ip_extraction
from guard_core.models import SecurityConfig
from guard_core.utils import _extract_from_forwarded_header, extract_client_ip
from tests.conftest import MockGuardRequest


@pytest.fixture(autouse=True)
def _reset_forwarded_header_preemption_warning() -> None:
    ip_extraction._forwarded_header_preemption_warned = False


async def test_extract_client_ip_without_trusted_proxies() -> None:
    config = SecurityConfig()

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


async def test_extract_client_ip_with_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "1.2.3.4"


async def test_extract_client_ip_with_cidr_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.0/8"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "1.2.3.4"


async def test_extract_client_ip_with_proxy_depth() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "5.6.7.8"


async def test_extract_client_ip_without_xforwarded() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


async def test_extract_client_ip_with_untrusted_proxy() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


async def test_extract_client_ip_error_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "invalid-ip"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        with patch(
            "guard_core._utils.ip_extraction.ip_address",
            side_effect=ValueError("Invalid IP"),
        ):
            ip = await extract_client_ip(request, config)
            assert ip == "127.0.0.1"
            assert "Potential IP spoof attempt" in caplog.text


async def test_extract_client_ip_no_client() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host=None,
    )

    ip = await extract_client_ip(request, config)
    assert ip == "unknown"


async def test_extract_client_ip_unix_socket_resolves_from_forwarded_header() -> None:
    config = SecurityConfig(trusted_proxies=["unix"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host=None,
    )

    ip = await extract_client_ip(request, config)
    assert ip == "1.2.3.4"


async def test_extract_client_ip_unix_socket_without_header_stays_unknown() -> None:
    config = SecurityConfig(trusted_proxies=["unix"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host=None,
    )

    ip = await extract_client_ip(request, config)
    assert ip == "unknown"


async def test_extract_client_ip_fallback_to_connecting_ip() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


async def test_extract_client_ip_untrusted_without_forwarded() -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


PREEMPTION_WARNING_TEXT = "already appears inside its own X-Forwarded-For chain"


async def test_preemption_warning_fires_when_trusted_proxies_unset(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "9.9.0.1"},
        client_host="9.9.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "9.9.0.1"
    assert PREEMPTION_WARNING_TEXT in caplog.text


async def test_preemption_warning_fires_in_untrusted_peer_branch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "9.9.0.1, 1.2.3.4"},
        client_host="9.9.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "9.9.0.1"
    assert PREEMPTION_WARNING_TEXT in caplog.text
    assert "Potential IP spoof attempt" in caplog.text


async def test_preemption_warning_absent_without_forwarded_header(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="9.9.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "9.9.0.1"
    assert PREEMPTION_WARNING_TEXT not in caplog.text


async def test_preemption_warning_absent_when_peer_not_in_chain(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "127.0.0.1"
    assert PREEMPTION_WARNING_TEXT not in caplog.text


async def test_preemption_warning_emitted_at_most_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            request = MockGuardRequest(
                path="/",
                method="GET",
                headers={"X-Forwarded-For": "9.9.0.1"},
                client_host="9.9.0.1",
            )
            ip = await extract_client_ip(request, config)
            assert ip == "9.9.0.1"

    assert caplog.text.count(PREEMPTION_WARNING_TEXT) == 1


CHAIN_TOO_SHORT_WARNING_TEXT = "chain has only"


@pytest.fixture(autouse=True)
def _reset_chain_too_short_warning() -> None:
    ip_extraction._forwarded_header_chain_too_short_warned = False


async def test_chain_too_short_warning_fires_on_depth_exceeding_chain_length(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "127.0.0.1"
    assert CHAIN_TOO_SHORT_WARNING_TEXT in caplog.text
    assert "trusted_proxy_depth is 3" in caplog.text


async def test_chain_too_short_warning_absent_when_chain_meets_depth(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "5.6.7.8"
    assert CHAIN_TOO_SHORT_WARNING_TEXT not in caplog.text


async def test_chain_too_short_warning_emitted_at_most_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            request = MockGuardRequest(
                path="/",
                method="GET",
                headers={"X-Forwarded-For": "1.2.3.4"},
                client_host="127.0.0.1",
            )
            await extract_client_ip(request, config)

    assert caplog.text.count(CHAIN_TOO_SHORT_WARNING_TEXT) == 1


SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT = "is itself listed in trusted_proxies"


@pytest.fixture(autouse=True)
def _reset_selected_entry_trusted_proxy_warning() -> None:
    ip_extraction._forwarded_header_selected_entry_trusted_proxy_warned = False


async def test_selected_entry_trusted_proxy_warning_fires_on_overcounted_depth(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "10.0.0.1"], trusted_proxy_depth=2
    )

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "10.0.0.1, 1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "10.0.0.1"
    assert SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT in caplog.text


async def test_selected_entry_trusted_proxy_warning_absent_for_real_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=1)

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        client_host="127.0.0.1",
    )

    with caplog.at_level(logging.WARNING):
        ip = await extract_client_ip(request, config)

    assert ip == "1.2.3.4"
    assert SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT not in caplog.text


async def test_selected_entry_trusted_proxy_warning_emitted_at_most_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        trusted_proxies=["127.0.0.1", "10.0.0.1"], trusted_proxy_depth=2
    )

    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            request = MockGuardRequest(
                path="/",
                method="GET",
                headers={"X-Forwarded-For": "10.0.0.1, 1.2.3.4"},
                client_host="127.0.0.1",
            )
            await extract_client_ip(request, config)

    assert caplog.text.count(SELECTED_ENTRY_TRUSTED_PROXY_WARNING_TEXT) == 1


GLOB_METACHARACTERS = ("*", "?", "[", "]", "\\")


@pytest.mark.parametrize(
    "forwarded_for, proxy_depth",
    [
        ("", 1),
        ("*", 1),
        ("?", 1),
        ("[", 1),
        ("*:*", 1),
        ("*:*:*", 1),
        ("evil*", 1),
        ("*\n", 1),
        ("*, 5.6.7.8", 2),
        ("[evil, 5.6.7.8", 2),
        ("not-an-ip", 1),
        ("1.2.3.4", 3),
    ],
)
async def test_extract_from_forwarded_header_rejects_non_ip_entries(
    forwarded_for: str, proxy_depth: int
) -> None:
    assert _extract_from_forwarded_header(forwarded_for, proxy_depth) is None


@pytest.mark.parametrize(
    "forwarded_for, proxy_depth, expected",
    [
        ("5.6.7.8", 1, "5.6.7.8"),
        ("5.6.7.8, 1.2.3.4", 2, "5.6.7.8"),
        ("::1", 1, "::1"),
        ("2001:db8::1", 1, "2001:db8::1"),
        ("[::1]", 1, "::1"),
        ("[2001:db8::1]", 1, "2001:db8::1"),
        ("fe80::1%eth0", 1, "fe80::1%eth0"),
    ],
)
async def test_extract_from_forwarded_header_returns_valid_ips(
    forwarded_for: str, proxy_depth: int, expected: str
) -> None:
    assert _extract_from_forwarded_header(forwarded_for, proxy_depth) == expected


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "fe80::1%*",
        "fe80::1%[",
        "fe80::1%]",
        "fe80::1%?",
        "fe80::1%\\",
        "fe80::1%[a]b",
    ],
)
async def test_extract_from_forwarded_header_rejects_glob_in_ipv6_zone_id(
    forwarded_for: str,
) -> None:
    assert _extract_from_forwarded_header(forwarded_for, 1) is None


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "*",
        "?",
        "[",
        "evil*",
        "*:*",
        "*:*:*",
        "*, 1.2.3.4",
        "*\n, 1.2.3.4",
        "fe80::1%*, 1.2.3.4",
        "fe80::1%[, 1.2.3.4",
        "fe80::1%], 1.2.3.4",
        "fe80::1%?, 1.2.3.4",
        "fe80::1%\\, 1.2.3.4",
        "fe80::1%[a]b, 1.2.3.4",
    ],
)
async def test_extract_client_ip_sanitizes_glob_metacharacters_from_xff(
    forwarded_for: str,
) -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": forwarded_for},
        client_host="127.0.0.1",
    )

    ip = await extract_client_ip(request, config)

    assert ip == "127.0.0.1"
    assert not any(char in ip for char in GLOB_METACHARACTERS)
