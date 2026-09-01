import logging
from collections.abc import Iterator
from typing import Any

import pytest

from guard_core.sync._utils.block_events import (
    ON_BLOCK_EXCLUDED_CHECK_NAMES,
    fire_block_hook,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import SyncMockGuardRequest


class AwaitableSignal:
    def __await__(self) -> Iterator[None]:
        return iter(())


def test_sync_fire_block_hook_rejects_awaitable_hook() -> None:
    requests: list[SyncGuardRequest] = []

    def hook(request: SyncGuardRequest, payload: dict[str, Any]) -> AwaitableSignal:
        requests.append(request)
        return AwaitableSignal()

    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")
    request.state.client_ip = "203.0.113.7"

    with pytest.raises(
        TypeError,
        match=r"async on_block hook not supported in sync \(WSGI\) deployments",
    ):
        fire_block_hook(hook, request, "ip_security", "blacklisted", "", False, 403)

    assert requests == [request]


def test_sync_fire_block_hook_rejects_deferred_awaitable_hook() -> None:
    def hook(request: SyncGuardRequest, payload: dict[str, Any]) -> AwaitableSignal:
        return AwaitableSignal()

    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    with pytest.raises(TypeError, match="supply a sync on_block hook"):
        fire_block_hook(hook, request, "ip_security", "blacklisted", "", False, 403)


def test_sync_fire_block_hook_invokes_sync_hook_with_payload() -> None:
    calls: list[dict[str, Any]] = []

    def hook(request: SyncGuardRequest, payload: dict[str, Any]) -> None:
        calls.append(payload)

    request = SyncMockGuardRequest(path="/api/x", method="POST", client_host="10.0.0.1")
    request.state.client_ip = "203.0.113.7"

    fire_block_hook(hook, request, "ip_security", "blacklisted", "IPMatch", False, 403)

    assert calls == [
        {
            "check_name": "ip_security",
            "reason": "blacklisted",
            "trigger_info": "IPMatch",
            "passive_mode": False,
            "client_ip": "203.0.113.7",
            "path": "/api/x",
            "method": "POST",
            "status_code": 403,
        }
    ]


def test_sync_fire_block_hook_with_no_hook_is_a_no_op() -> None:
    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    fire_block_hook(None, request, "ip_security", "blacklisted", "", False, 403)


def test_sync_fire_block_hook_swallows_hook_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def hook(request: SyncGuardRequest, payload: dict[str, Any]) -> None:
        raise RuntimeError("hook exploded")

    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    with caplog.at_level(logging.ERROR, logger="guard_core"):
        fire_block_hook(hook, request, "ip_security", "blacklisted", "", False, 403)

    assert "on_block hook raised" in caplog.text
    assert "hook exploded" in caplog.text


@pytest.mark.parametrize("check_name", sorted(ON_BLOCK_EXCLUDED_CHECK_NAMES))
def test_sync_fire_block_hook_skips_excluded_check_names(check_name: str) -> None:
    calls: list[dict[str, Any]] = []

    def hook(request: SyncGuardRequest, payload: dict[str, Any]) -> None:
        calls.append(payload)

    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    fire_block_hook(
        hook, request, check_name, "validator rejected", "trigger", False, 403
    )

    assert calls == []


def test_sync_build_block_payload_prefers_state_cached_client_ip() -> None:
    request = SyncMockGuardRequest(path="/", method="GET", client_host="127.0.0.1")
    request.state.client_ip = "203.0.113.7"

    payload = _payload(request)

    assert payload["client_ip"] == "203.0.113.7"
    assert payload["check_name"] == "ip_security"
    assert payload["path"] == "/"
    assert payload["method"] == "GET"


def test_sync_build_block_payload_canonicalizes_connecting_ip() -> None:
    request = SyncMockGuardRequest(
        path="/", method="GET", client_host="::ffff:203.0.113.9"
    )

    payload = _payload(request)

    assert payload["client_ip"] == "203.0.113.9"


def test_sync_build_block_payload_falls_back_to_unknown_identity() -> None:
    request = SyncMockGuardRequest(path="/", method="GET", client_host=None)

    payload = _payload(request)

    assert payload["client_ip"] == "unknown"


def _payload(request: SyncMockGuardRequest) -> dict:
    from guard_core.sync._utils.block_events import build_block_payload

    return build_block_payload(request, "ip_security", "", "", False, 403)
