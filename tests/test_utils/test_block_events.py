import logging

import pytest

from guard_core._utils.block_events import (
    ON_BLOCK_EXCLUDED_CHECK_NAMES,
    fire_block_hook,
    invoke_block_hook,
)
from tests.conftest import MockGuardRequest


def test_excluded_check_names_are_the_application_authored_and_redirects_only() -> None:
    assert ON_BLOCK_EXCLUDED_CHECK_NAMES == frozenset(
        {"custom_request", "custom_validators", "https_enforcement"}
    )


async def test_invoke_block_hook_with_no_hook_is_a_total_no_op() -> None:
    request = MockGuardRequest(path="/a", method="POST", client_host="10.0.0.1")

    assert await invoke_block_hook(None, request, {}) is None


async def test_fire_block_hook_with_no_hook_is_a_no_op() -> None:
    request = MockGuardRequest(path="/a", method="POST", client_host="10.0.0.1")

    assert (
        await fire_block_hook(None, request, "ip_security", "banned", "", False, 403)
        is None
    )


@pytest.mark.parametrize("check_name", sorted(ON_BLOCK_EXCLUDED_CHECK_NAMES))
async def test_fire_block_hook_skips_excluded_check_names(check_name: str) -> None:
    calls: list[dict] = []

    def hook(request: MockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    request = MockGuardRequest(path="/a", method="GET", client_host="10.0.0.1")

    await fire_block_hook(hook, request, check_name, "reason", "", False, 403)

    assert calls == []


async def test_fire_block_hook_skips_excluded_check_name_even_with_reason() -> None:
    calls: list[dict] = []

    def hook(request: MockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    request = MockGuardRequest(path="/a", method="GET", client_host="10.0.0.1")

    await fire_block_hook(
        hook, request, "custom_validators", "validator rejected", "trigger", False, 403
    )

    assert calls == []


async def test_fire_block_hook_invokes_hook_with_full_payload() -> None:
    calls: list[dict] = []

    def hook(request: MockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    request = MockGuardRequest(path="/api/x", method="POST", client_host="10.0.0.1")
    request.state.client_ip = "203.0.113.7"

    await fire_block_hook(
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


async def test_fire_block_hook_passes_request_to_hook() -> None:
    seen_requests: list[MockGuardRequest] = []
    request = MockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    def hook(hook_request: MockGuardRequest, payload: dict) -> None:
        seen_requests.append(hook_request)

    await fire_block_hook(hook, request, "ip_security", "r", "", False, 403)

    assert seen_requests == [request]


async def test_fire_block_hook_awaits_async_hook() -> None:  # async-only
    completed: list[dict] = []
    payload_passed: list[dict] = []

    async def hook(request: MockGuardRequest, payload: dict) -> None:
        payload_passed.append(payload)
        completed.append(dict(payload))

    request = MockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    await fire_block_hook(hook, request, "ip_security", "r", "t", True, None)

    assert completed == payload_passed
    assert completed[0]["passive_mode"] is True
    assert completed[0]["status_code"] is None


async def test_fire_block_hook_swallows_hook_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def hook(request: MockGuardRequest, payload: dict) -> None:
        raise RuntimeError("hook exploded")

    request = MockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    with caplog.at_level(logging.ERROR, logger="guard_core"):
        result = await fire_block_hook(
            hook, request, "ip_security", "r", "", False, 403
        )

    assert result is None
    assert "on_block hook raised" in caplog.text
    assert "hook exploded" in caplog.text


async def test_build_block_payload_prefers_state_cached_client_ip() -> None:
    request = MockGuardRequest(path="/", method="GET", client_host="127.0.0.1")
    request.state.client_ip = "203.0.113.7"

    payload = await _payload(request, "ip_security")

    assert payload["client_ip"] == "203.0.113.7"


async def test_build_block_payload_canonicalizes_connecting_ip() -> None:
    request = MockGuardRequest(path="/", method="GET", client_host="::ffff:203.0.113.9")

    payload = await _payload(request, "ip_security")

    assert payload["client_ip"] == "203.0.113.9"


async def test_build_block_payload_falls_back_to_unknown_identity() -> None:
    request = MockGuardRequest(path="/", method="GET", client_host=None)

    payload = await _payload(request, "ip_security")

    assert payload["client_ip"] == "unknown"


async def _payload(request: MockGuardRequest, check_name: str) -> dict:
    captured: list[dict] = []

    def hook(hook_request: MockGuardRequest, payload: dict) -> None:
        captured.append(payload)

    await fire_block_hook(hook, request, check_name, "", "", False, 403)

    return captured[0]
