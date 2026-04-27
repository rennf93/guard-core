from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class MockCheck(SecurityCheck):
    def __init__(self, middleware: Mock, name: str, should_block: bool = False) -> None:
        super().__init__(middleware)
        self._name = name
        self._should_block = should_block

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if self._should_block:
            return cast(GuardResponse, Mock(status_code=403))
        return None


class FailingCheck(SecurityCheck):
    def __init__(self, middleware: Mock, name: str = "failing_check") -> None:
        super().__init__(middleware)
        self._name = name

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        raise ValueError("Check error")


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.fail_secure = False
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=500))
    return middleware


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.url_path = "/test"
    request.method = "GET"
    return request


def test_pipeline_initialization(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")

    pipeline = SecurityCheckPipeline([check1, check2])

    assert len(pipeline) == 2
    assert pipeline.get_check_names() == ["check1", "check2"]


async def test_execute_all_checks_pass(
    mock_middleware: Mock, mock_request: Mock
) -> None:
    check1 = MockCheck(mock_middleware, "check1", should_block=False)
    check2 = MockCheck(mock_middleware, "check2", should_block=False)

    pipeline = SecurityCheckPipeline([check1, check2])
    result = await pipeline.execute(mock_request)

    assert result is None


async def test_execute_first_check_blocks(
    mock_middleware: Mock, mock_request: Mock
) -> None:
    check1 = MockCheck(mock_middleware, "check1", should_block=True)
    check2 = MockCheck(mock_middleware, "check2", should_block=False)

    pipeline = SecurityCheckPipeline([check1, check2])
    result = await pipeline.execute(mock_request)

    assert result is not None
    assert result.status_code == 403


async def test_execute_second_check_blocks(
    mock_middleware: Mock, mock_request: Mock
) -> None:
    check1 = MockCheck(mock_middleware, "check1", should_block=False)
    check2 = MockCheck(mock_middleware, "check2", should_block=True)

    pipeline = SecurityCheckPipeline([check1, check2])
    result = await pipeline.execute(mock_request)

    assert result is not None
    assert result.status_code == 403


async def test_execute_with_exception_fail_open(
    mock_middleware: Mock, mock_request: Mock
) -> None:
    failing_check = FailingCheck(mock_middleware, "failing_check")
    passing_check = MockCheck(mock_middleware, "passing_check", should_block=False)

    mock_middleware.config.fail_secure = False

    pipeline = SecurityCheckPipeline([failing_check, passing_check])
    result = await pipeline.execute(mock_request)

    assert result is None


async def test_execute_with_exception_fail_secure(
    mock_middleware: Mock, mock_request: Mock
) -> None:
    failing_check = FailingCheck(mock_middleware, "failing_check")
    passing_check = MockCheck(mock_middleware, "passing_check", should_block=False)

    mock_middleware.config.fail_secure = True

    pipeline = SecurityCheckPipeline([failing_check, passing_check])
    result = await pipeline.execute(mock_request)

    assert result is not None
    assert result.status_code == 500


async def test_execute_with_exception_fail_secure_false_falls_through(
    mock_middleware: Mock, mock_request: Mock
) -> None:
    failing_check = FailingCheck(mock_middleware, "failing_check")

    mock_middleware.config.fail_secure = False

    pipeline = SecurityCheckPipeline([failing_check])
    result = await pipeline.execute(mock_request)

    assert result is None


def test_add_check(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")

    pipeline = SecurityCheckPipeline([check1])
    assert len(pipeline) == 1

    pipeline.add_check(check2)
    assert len(pipeline) == 2
    assert pipeline.get_check_names() == ["check1", "check2"]


def test_insert_check(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")
    check3 = MockCheck(mock_middleware, "check3")

    pipeline = SecurityCheckPipeline([check1, check3])
    pipeline.insert_check(1, check2)

    assert len(pipeline) == 3
    assert pipeline.get_check_names() == ["check1", "check2", "check3"]


def test_remove_check_found(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")
    check3 = MockCheck(mock_middleware, "check3")

    pipeline = SecurityCheckPipeline([check1, check2, check3])
    result = pipeline.remove_check("check2")

    assert result is True
    assert len(pipeline) == 2
    assert pipeline.get_check_names() == ["check1", "check3"]


def test_remove_check_not_found(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")

    pipeline = SecurityCheckPipeline([check1])
    result = pipeline.remove_check("nonexistent")

    assert result is False
    assert len(pipeline) == 1


def test_get_check_names(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")

    pipeline = SecurityCheckPipeline([check1, check2])
    names = pipeline.get_check_names()

    assert names == ["check1", "check2"]


def test_len(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")

    pipeline = SecurityCheckPipeline([check1, check2])

    assert len(pipeline) == 2


def test_repr(mock_middleware: Mock) -> None:
    check1 = MockCheck(mock_middleware, "check1")
    check2 = MockCheck(mock_middleware, "check2")

    pipeline = SecurityCheckPipeline([check1, check2])
    repr_str = repr(pipeline)

    assert "SecurityCheckPipeline" in repr_str
    assert "2 checks" in repr_str
    assert "check1" in repr_str
    assert "check2" in repr_str


@pytest.mark.parametrize(
    "checks,expected_count",
    [
        ([], 0),
        (["check1"], 1),
        (["check1", "check2"], 2),
        (["check1", "check2", "check3"], 3),
    ],
)
def test_pipeline_various_sizes(
    mock_middleware: Mock, checks: list[str], expected_count: int
) -> None:
    check_objects: list[SecurityCheck] = [
        MockCheck(mock_middleware, name) for name in checks
    ]
    pipeline = SecurityCheckPipeline(check_objects)

    assert len(pipeline) == expected_count
    assert pipeline.get_check_names() == checks


async def test_pipeline_skips_block_log_when_check_is_muted(
    mock_middleware: Mock, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    pipeline = SecurityCheckPipeline(
        [MockCheck(mock_middleware, "muted_check", should_block=True)],
        muted_check_logs={"muted_check"},
    )
    request = Mock()
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()

    with caplog.at_level(logging.INFO):
        result = await pipeline.execute(request)
    assert result is not None
    assert not any("Request blocked by" in r.getMessage() for r in caplog.records)


async def test_pipeline_skips_error_log_when_check_is_muted(
    mock_middleware: Mock, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    pipeline = SecurityCheckPipeline(
        [FailingCheck(mock_middleware, name="muted_fail")],
        muted_check_logs={"muted_fail"},
    )
    request = Mock()
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()

    with caplog.at_level(logging.ERROR):
        await pipeline.execute(request)
    assert not any("Error in security check" in r.getMessage() for r in caplog.records)


async def test_pipeline_skips_fail_secure_log_when_check_is_muted(
    mock_middleware: Mock, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    failing = FailingCheck(mock_middleware, name="muted_fs")
    failing.config.fail_secure = True
    cast(Any, failing).create_error_response = AsyncMock(
        return_value=Mock(status_code=500)
    )

    pipeline = SecurityCheckPipeline(
        [failing],
        muted_check_logs={"muted_fs"},
    )
    request = Mock()
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()

    with caplog.at_level(logging.WARNING):
        await pipeline.execute(request)
    assert not any(
        "Blocking request due to check error" in r.getMessage() for r in caplog.records
    )
