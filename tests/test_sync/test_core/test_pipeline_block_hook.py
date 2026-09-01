from typing import cast
from unittest.mock import Mock

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import SyncMockGuardRequest


class BlockingCheck(SecurityCheck):
    def __init__(self, middleware: Mock, name: str) -> None:
        super().__init__(middleware)
        self._name = name

    @property
    def check_name(self) -> str:
        return self._name

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return cast(GuardResponse, Mock(status_code=403))


def make_pipeline(hook: None | object) -> tuple[SecurityCheckPipeline, BlockingCheck]:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.on_block = hook
    middleware.config.fail_secure = False
    middleware.config.redis_fail_open = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = Mock()

    check = BlockingCheck(middleware, "ip_security")
    return SecurityCheckPipeline([check]), check


def test_block_decision_fires_hook_once_with_status_and_stash_details() -> None:
    calls: list[dict] = []

    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    pipeline, _ = make_pipeline(hook)
    request = SyncMockGuardRequest(path="/api/x", method="POST", client_host="10.0.0.1")
    request.state._guard_block_stash = {
        "reason": "blacklisted ip",
        "trigger_info": "IPMatch",
    }

    response = pipeline.execute(request)

    assert response is not None
    assert response.status_code == 403
    assert len(calls) == 1
    assert calls[0]["check_name"] == "ip_security"
    assert calls[0]["reason"] == "blacklisted ip"
    assert calls[0]["trigger_info"] == "IPMatch"
    assert calls[0]["passive_mode"] is False
    assert calls[0]["status_code"] == 403


def test_block_decision_with_missing_stash_fires_hook_with_empty_details() -> None:
    calls: list[dict] = []

    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    pipeline, _ = make_pipeline(hook)
    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")

    pipeline.execute(request)

    assert len(calls) == 1
    assert calls[0]["reason"] == ""
    assert calls[0]["trigger_info"] == ""
    assert calls[0]["status_code"] == 403


def test_block_decision_with_none_stash_still_fires_hook() -> None:
    calls: list[dict] = []

    def hook(request: SyncMockGuardRequest, payload: dict) -> None:
        calls.append(payload)

    pipeline, _ = make_pipeline(hook)
    request = SyncMockGuardRequest(path="/", method="GET", client_host="10.0.0.1")
    request.state._guard_block_stash = None

    pipeline.execute(request)

    assert len(calls) == 1
    assert calls[0]["reason"] == ""
    assert calls[0]["trigger_info"] == ""
