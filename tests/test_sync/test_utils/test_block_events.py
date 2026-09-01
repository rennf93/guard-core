import logging

import pytest

from guard_core.sync._utils.block_events import (
    ON_BLOCK_EXCLUDED_CHECK_NAMES,
    fire_block_hook,
    invoke_block_hook,
)
from tests.test_sync.conftest import SyncMockGuardRequest


def test_excluded_check_names_are_the_application_authored_and_redirects_only() -> None:
    assert ON_BLOCK_EXCLUDED_CHECK_NAMES == frozenset(
        {"custom_request", "custom_validators", "https_enforcement"}
    )


def test_invoke_block_hook_with_no_hook_is_a_total_no_op() -> None:
    request = SyncMockGuardRequest(path="/a", method="POST", client_host="10.0.0.1")

    assert invoke_block_hook(None, request, {}) is None


def test_fire_block_hook_with_no_hook_is_a_no_op() -> None:
    request = SyncMockGuardRequest(path="/a", method="POST", client_host="10.0.0.1")

    assert (
        fire_block_hook(None, request, "ip_security", "banned", "", False, 403) is None
    )


@pytest.mark.parametrize("check_name", sorted(ON_BLOCK_EXCLUDED_CHECK_NAMES))
def test_fire_block_hook_skips_excluded_check_names(check_name: str) -> None:
    calls: list[dict] = []

    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    request = SyncMockGuardRequest(path="/a", method="GET", client_host="10.0.0.1")

    fire_block_hook(hook, request, check_name, "reason", "", False, 403)

    assert calls == []


def test_fire_block_hook_skips_excluded_check_name_even_with_reason() -> None:
    calls: list[dict] = []

    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    request = SyncMockGuardRequest(path="/a", method="GET", client_host="10.0.0.1")

    fire_block_hook(
        hook, request, "custom_validators", "validator rejected", "trigger", False, 403
    )

    assert calls == []


def test_fire_block_hook_invokes_hook_with_full_payload() -> None:
    calls: list[dict] = []

    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    request = SyncMockGuardRequest(path="/api/x", method="POST", client_host="10.0.0.1")
    request.state.client_ip = "203.0.113.7"

    fire_block_hook(
        hook, request, "ip_security", "blacklisted ip", "IPMatch", False, 403
    )

    assert calls == [
        {
            "check_name": "ip_security",
            "reason": "blacklisted ip",
            "trigger_info": "IPMatch",
            "passive_mode": False,
            "client_ip": "203.0.113.7",
            "path": "/api/x",
            "method": "POST",
            "status_code": 403,
        }
    ]


def test_fire_block_hook_passes_request_to_hook() -> None:
    seen_requests: list[SyncMockGuardRequest] = []
    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    def hook(hook_request: SyncMockGuardRequest, payload: dict) -> None:
        seen_requests.append(hook_request)

    fire_block_hook(hook, request, "ip_security", "r", "", False, 403)

    assert seen_requests == [request]


def test_fire_block_hook_swallows_hook_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        raise RuntimeError("hook exploded")

    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    with caplog.at_level(logging.ERROR, logger="guard_core"):
        result = fire_block_hook(hook, request, "ip_security", "r", "", False, 403)

    assert result is None
    assert "on_block hook raised" in caplog.text
    assert "hook exploded" in caplog.text


def test_build_block_payload_prefers_state_cached_client_ip() -> None:
    request = SyncMockGuardRequest(path="/", method="GET", client_host="127.0.0.1")
    request.state.client_ip = "203.0.113.7"

    payload = _payload(request, "ip_security")

    assert payload["client_ip"] == "203.0.113.7"


def test_build_block_payload_canonicalizes_connecting_ip() -> None:
    request = SyncMockGuardRequest(
        path="/", method="GET", client_host="::ffff:203.0.113.9"
    )

    payload = _payload(request, "ip_security")

    assert payload["client_ip"] == "203.0.113.9"


def test_build_block_payload_falls_back_to_unknown_identity() -> None:
    request = SyncMockGuardRequest(path="/", method="GET", client_host=None)

    payload = _payload(request, "ip_security")

    assert payload["client_ip"] == "unknown"


def _payload(request: SyncMockGuardRequest, check_name: str) -> dict:
    captured: list[dict] = []

    def hook(hook_request: SyncMockGuardRequest, payload: dict) -> None:
        captured.append(payload)

    fire_block_hook(hook, request, check_name, "", "", False, 403)

    return captured[0]
