import logging
import os
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from pytest_mock import MockerFixture

from guard_core.models import SecurityConfig
from guard_core.sync.utils import (
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)
from tests.test_sync.conftest import SyncMockGuardRequest


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture(autouse=True)
def _restore_logger_state() -> Iterator[None]:
    root_logger = logging.getLogger()
    guard_logger = logging.getLogger("guard_core")
    original_root_handlers = root_logger.handlers[:]
    original_root_level = root_logger.level
    original_guard_handlers = guard_logger.handlers[:]
    original_guard_level = guard_logger.level
    original_guard_propagate = guard_logger.propagate
    yield
    for handler in guard_logger.handlers[:]:
        if handler not in original_guard_handlers:
            handler.close()
    guard_logger.handlers = original_guard_handlers
    guard_logger.setLevel(original_guard_level)
    guard_logger.propagate = original_guard_propagate
    for handler in root_logger.handlers[:]:
        if handler not in original_root_handlers:
            handler.close()
    root_logger.handlers = original_root_handlers
    root_logger.setLevel(original_root_level)


def test_is_ip_allowed(security_config: SecurityConfig, mocker: MockerFixture) -> None:
    mocker.patch("guard_core.sync.utils.check_ip_country", return_value=False)

    assert is_ip_allowed("127.0.0.1", security_config)
    assert not is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(whitelist=[], blacklist=[])
    assert is_ip_allowed("127.0.0.1", empty_config)
    assert is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(whitelist=["127.0.0.1"])
    assert is_ip_allowed("127.0.0.1", whitelist_config)
    assert not is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(blacklist=["192.168.1.1"])
    assert is_ip_allowed("127.0.0.1", blacklist_config)
    assert not is_ip_allowed("192.168.1.1", blacklist_config)


def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    assert is_user_agent_allowed("goodbot", security_config)
    assert not is_user_agent_allowed("badbot", security_config)


def test_custom_logging(security_config: SecurityConfig, tmp_path: Any) -> None:
    log_file = tmp_path / "test_log.log"
    logger = setup_custom_logging(str(log_file))

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    log_activity(request, logger)

    with open(log_file) as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET https://test/" in log_content


def test_detected_component_with_lone_surrogate_writes_intact_log_line(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "audit.log"
    setup_custom_logging(str(log_file))

    body = b"\x88cshutil\nrmtree\n(S'/tmp/x'\ntR."
    request = SyncMockGuardRequest(
        method="POST",
        headers={"content-length": str(len(body))},
        body_content=body,
    )

    result = detect_penetration_attempt(request, SecurityConfig())
    assert result.is_threat is True

    with open(log_file, encoding="utf-8") as f:
        log_content = f.read()
    assert log_content, "audit log entry was silently dropped"
    assert "Potential attack detected" in log_content
    assert "\\x88" in log_content
    assert "\udc88" not in log_content


def test_detect_penetration_attempt_attributes_real_client_ip_behind_proxy(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "audit.log"
    setup_custom_logging(str(log_file))

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "203.0.113.7", "user-agent": "test-agent"},
        client_host="10.0.0.1",
        query_params={"q": "<script>alert(1)</script>"},
    )

    config = SecurityConfig(trusted_proxies=["10.0.0.1"], trusted_proxy_depth=1)
    result = detect_penetration_attempt(request, config)
    assert result.is_threat is True

    with open(log_file, encoding="utf-8") as f:
        log_content = f.read()
    detection_lines = [
        line for line in log_content.splitlines() if "Potential attack detected" in line
    ]
    assert detection_lines, "no detection log line written"
    for line in detection_lines:
        assert "Potential attack detected from 203.0.113.7" in line
        assert "from 10.0.0.1" not in line


def test_detect_penetration_attempt_falls_back_to_connecting_ip_without_config(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "audit.log"
    setup_custom_logging(str(log_file))

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="198.51.100.5",
        query_params={"q": "<script>alert(1)</script>"},
    )

    result = detect_penetration_attempt(request, None)
    assert result.is_threat is True

    with open(log_file, encoding="utf-8") as f:
        log_content = f.read()
    detection_lines = [
        line for line in log_content.splitlines() if "Potential attack detected" in line
    ]
    assert detection_lines, "no detection log line written"
    for line in detection_lines:
        assert "Potential attack detected from 198.51.100.5" in line


def test_log_request(caplog: pytest.LogCaptureFixture) -> None:
    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        log_activity(request, logger)

    assert "Request from 127.0.0.1: GET https://test/" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


def test_log_suspicious_activity(caplog: pytest.LogCaptureFixture) -> None:
    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
        )

    assert "Suspicious activity detected" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET https://test/" in caplog.text


def test_log_suspicious_activity_passive_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
            passive_mode=True,
            trigger_info="SQL injection attempt",
        )

    assert "[PASSIVE MODE] Penetration attempt detected from" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET https://test/" in caplog.text
    assert "Trigger: SQL injection attempt" in caplog.text


def test_log_custom_type(caplog: pytest.LogCaptureFixture) -> None:
    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        log_activity(
            request, logger, log_type="custom_event", reason="Custom event reason"
        )

    assert "Custom_event from 127.0.0.1: GET https://test/" in caplog.text
    assert "Details: Custom event reason" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


def test_setup_custom_logging_always_attaches_console_and_file_handlers(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "security.log"
    logger = setup_custom_logging(str(log_file))

    handler_count = sum(
        1
        for h in logger.handlers
        if isinstance(h, logging.FileHandler | logging.StreamHandler)
    )
    assert handler_count == 2


def test_no_duplicate_emission_when_root_is_configured_before_guard(
    capsys: pytest.CaptureFixture[str],
) -> None:
    logging.basicConfig(force=True)
    recorder = _RecordingHandler()
    logging.getLogger().addHandler(recorder)

    logger = setup_custom_logging(None, "json")
    console_handler = logger.handlers[0]
    assert isinstance(console_handler, logging.StreamHandler)

    capsys.readouterr()
    logger.warning("root-first-line")

    assert len(recorder.records) == 1
    assert recorder.records[0].getMessage() == "root-first-line"
    assert console_handler.filter(recorder.records[0]) is False

    captured = capsys.readouterr()
    matching_lines = [
        line for line in captured.err.splitlines() if "root-first-line" in line
    ]
    assert len(matching_lines) == 1
    assert not matching_lines[0].startswith("{")


def test_no_duplicate_emission_when_guard_is_configured_before_root(
    capsys: pytest.CaptureFixture[str],
) -> None:
    logging.getLogger().handlers = []
    logger = setup_custom_logging(None, "json")
    console_handler = logger.handlers[0]
    assert isinstance(console_handler, logging.StreamHandler)

    logging.basicConfig(force=True)
    recorder = _RecordingHandler()
    logging.getLogger().addHandler(recorder)

    capsys.readouterr()
    logger.warning("guard-first-line")

    assert len(recorder.records) == 1
    assert recorder.records[0].getMessage() == "guard-first-line"
    assert console_handler.filter(recorder.records[0]) is False

    captured = capsys.readouterr()
    matching_lines = [
        line for line in captured.err.splitlines() if "guard-first-line" in line
    ]
    assert len(matching_lines) == 1
    assert not matching_lines[0].startswith("{")


@pytest.mark.parametrize(
    ("log_format", "expects_json"),
    [("text", False), ("json", True)],
)
def test_setup_custom_logging_emits_once_via_own_handler_when_root_has_no_handlers(
    capsys: pytest.CaptureFixture[str], log_format: str, expects_json: bool
) -> None:
    logging.getLogger().handlers = []

    logger = setup_custom_logging(None, log_format)
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.StreamHandler)
    assert logger.level == logging.INFO

    capsys.readouterr()
    logger.warning("solo-guard-line")

    captured = capsys.readouterr()
    matching_lines = [
        line for line in captured.err.splitlines() if "solo-guard-line" in line
    ]
    assert len(matching_lines) == 1
    if expects_json:
        assert matching_lines[0].startswith("{")
    else:
        assert matching_lines[0].startswith("[guard_core]")


@pytest.mark.parametrize(
    "ordering",
    ["root_configured_first", "guard_configured_first", "no_root_handlers"],
)
def test_custom_log_file_receives_the_line_in_every_root_handler_ordering(
    tmp_path: Any, ordering: str
) -> None:
    logging.getLogger().handlers = []
    log_file = tmp_path / "audit.log"

    if ordering == "root_configured_first":
        logging.getLogger().addHandler(logging.NullHandler())
        logger = setup_custom_logging(str(log_file))
    elif ordering == "guard_configured_first":
        logger = setup_custom_logging(str(log_file))
        logging.getLogger().addHandler(logging.NullHandler())
    else:
        logger = setup_custom_logging(str(log_file))

    logger.warning("file-line")

    with open(log_file) as f:
        content = f.read()
    assert "file-line" in content


def test_repeated_setup_does_not_stack_handlers_or_filters() -> None:
    setup_custom_logging(None)
    logger = setup_custom_logging(None)
    handler_count_first_call = len(logger.handlers)
    console_handler = logger.handlers[0]
    assert len(console_handler.filters) == 1
    assert logger.level == logging.INFO

    logger = setup_custom_logging(None)
    assert len(logger.handlers) == handler_count_first_call
    new_console_handler = logger.handlers[0]
    assert len(new_console_handler.filters) == 1
    assert logger.level == logging.INFO


def test_no_duplicate_logs(caplog: pytest.LogCaptureFixture, tmp_path: Any) -> None:
    log_file = tmp_path / "test_no_duplicates.log"

    guard_logger = setup_custom_logging(str(log_file))

    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers.copy()
    original_level = root_logger.level

    root_handler = logging.StreamHandler()
    root_handler.setFormatter(logging.Formatter("ROOT: %(message)s"))
    root_logger.addHandler(root_handler)
    root_logger.setLevel(logging.INFO)

    try:
        caplog.clear()
        caplog.set_level(logging.INFO)

        test_message = "Test message for duplicate check"
        guard_logger.info(test_message)

        matching_records = [r for r in caplog.records if test_message in r.message]

        assert len(matching_records) > 0, "Message should be logged"

        seen = set()
        for record in matching_records:
            key = (record.name, record.message, record.levelname)
            assert key not in seen, f"Duplicate log found: {key}"
            seen.add(key)

        with open(log_file) as f:
            file_content = f.read()
            assert test_message in file_content
            assert file_content.count(test_message) == 1, (
                "Message should appear once in log file"
            )

    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_hierarchical_namespace_isolation() -> None:
    guard_logger = logging.getLogger("fastapi_guard")
    guard_handler_logger = logging.getLogger("fastapi_guard.handlers.redis")
    user_logger = logging.getLogger("myapp")

    assert guard_handler_logger.parent == guard_logger
    assert guard_logger.parent == logging.getLogger()
    assert user_logger.parent == logging.getLogger()

    assert guard_logger is not user_logger
    assert guard_handler_logger is not user_logger

    assert guard_logger.name == "fastapi_guard"
    assert guard_handler_logger.name == "fastapi_guard.handlers.redis"
    assert user_logger.name == "myapp"


def test_custom_log_file_configuration(tmp_path: Any) -> None:
    custom_log_path = tmp_path / "my_custom_security.log"
    logger = setup_custom_logging(str(custom_log_path))

    test_message = "Custom log file test"
    logger.info(test_message)

    assert custom_log_path.exists(), "Custom log file should be created"
    with open(custom_log_path) as f:
        content = f.read()
        assert test_message in content

    logger_no_file = setup_custom_logging(None)

    file_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.FileHandler)
    ]
    stream_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.StreamHandler)
    ]

    assert len(file_handlers) == 0, "Should have no file handlers when log_file is None"
    assert len(stream_handlers) >= 1, (
        "Should have at least one stream handler for console"
    )


def test_logger_output_reaches_caplog_with_and_without_log_file(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger_no_file = setup_custom_logging(None)

    caplog.clear()
    caplog.set_level(logging.INFO)

    test_message = "Console output test - no file"
    logger_no_file.info(test_message)

    assert test_message in caplog.text, "Console output should work without file"

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp_file:
        logger_with_file = setup_custom_logging(tmp_file.name)

        caplog.clear()
        test_message_2 = "Console output test - with file"
        logger_with_file.info(test_message_2)

        assert test_message_2 in caplog.text, "Console output should work with file"

        os.unlink(tmp_file.name)


def test_setup_custom_logging_creates_directory(tmp_path: Any) -> None:
    non_existent_dir = tmp_path / "logs" / "subdirectory" / "deep"
    log_file_path = non_existent_dir / "test.log"

    assert not non_existent_dir.exists(), "Directory should not exist initially"

    logger = setup_custom_logging(str(log_file_path))

    assert non_existent_dir.exists(), "Directory should be created"

    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1, "Should have exactly one file handler"

    test_message = "Directory creation test"
    logger.info(test_message)

    assert log_file_path.exists(), "Log file should be created"
    with open(log_file_path) as f:
        content = f.read()
        assert test_message in content


def test_setup_custom_logging_file_handler_exception(
    caplog: pytest.LogCaptureFixture, mocker: MockerFixture
) -> None:
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch(
        "guard_core.sync._utils.logging_utils.logging.FileHandler",
        side_effect=PermissionError("Permission denied: cannot create log file"),
    )

    caplog.clear()
    caplog.set_level(logging.WARNING, logger="fastapi_guard")

    logger = setup_custom_logging("/invalid/path/test.log")

    assert "Failed to create log file /invalid/path/test.log" in caplog.text
    assert "Permission denied" in caplog.text or "cannot create log file" in caplog.text

    assert logger is not None

    assert len(logger.handlers) == 1, "Should have exactly one handler"
    assert isinstance(logger.handlers[0], logging.StreamHandler), (
        "Should have console handler"
    )

    caplog.clear()
    caplog.set_level(logging.INFO, logger="fastapi_guard")
    test_message = "Console still works after file handler failure"
    logger.info(test_message)
    assert test_message in caplog.text


def test_log_level(caplog: pytest.LogCaptureFixture) -> None:
    from typing import Literal

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)

    LOG_LEVELS: list[
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ] = [
        "INFO",
        "DEBUG",
        "WARNING",
        "ERROR",
        "CRITICAL",
        None,
    ]

    for level in LOG_LEVELS:
        caplog.clear()

        with caplog.at_level(logging.DEBUG):
            log_activity(request, logger, level=level)

        if level is not None:
            assert len(caplog.records) == 1
            assert caplog.records[0].levelname == level
        else:
            assert len(caplog.records) == 0


def test_behavior_tracker_passive_mode_logging(
    security_config: SecurityConfig,
) -> None:
    from typing import Literal

    from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker

    security_config.passive_mode = True
    tracker = BehaviorTracker(security_config)

    test_cases: list[tuple[Literal["ban", "log", "throttle", "alert"], str, str]] = [
        (
            "ban",
            "warning",
            "[PASSIVE MODE] Would ban IP 192.168.1.1 for behavioral "
            "violation: Test details",
        ),
        (
            "log",
            "warning",
            "[PASSIVE MODE] Behavioral anomaly detected: Test details",
        ),
        (
            "throttle",
            "warning",
            "[PASSIVE MODE] Would throttle IP 192.168.1.1: Test details",
        ),
        (
            "alert",
            "critical",
            "[PASSIVE MODE] ALERT - Behavioral anomaly: Test details",
        ),
    ]

    for action, log_level, expected_message in test_cases:
        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            action=action,
        )

        with patch.object(tracker.logger, log_level) as mock_logger:
            tracker.apply_action(
                rule=rule,
                client_ip="192.168.1.1",
                endpoint_id="/api/test",
                details="Test details",
            )

            mock_logger.assert_called_once_with(expected_message)
