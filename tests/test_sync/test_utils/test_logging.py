import logging
import os
from typing import Any
from unittest.mock import patch

import pytest
from pytest_mock import MockerFixture

from guard_core.models import SecurityConfig
from guard_core.sync.utils import (
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)
from tests.test_sync.conftest import SyncMockGuardRequest

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


def test_is_ip_allowed(security_config: SecurityConfig, mocker: MockerFixture) -> None:
    mocker.patch("guard_core.sync.utils.check_ip_country", return_value=False)

    assert is_ip_allowed("127.0.0.1", security_config)
    assert not is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, whitelist=[], blacklist=[])
    assert is_ip_allowed("127.0.0.1", empty_config)
    assert is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, whitelist=["127.0.0.1"]
    )
    assert is_ip_allowed("127.0.0.1", whitelist_config)
    assert not is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blacklist=["192.168.1.1"]
    )
    assert is_ip_allowed("127.0.0.1", blacklist_config)
    assert not is_ip_allowed("192.168.1.1", blacklist_config)


def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    assert is_user_agent_allowed("goodbot", security_config)
    assert not is_user_agent_allowed("badbot", security_config)


def test_custom_logging(
    reset_state: None, security_config: SecurityConfig, tmp_path: Any
) -> None:
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


def test_setup_custom_logging() -> None:
    log_file = os.path.join(os.getcwd(), "security.log")
    logger = setup_custom_logging(log_file)

    handler_count = sum(
        1
        for h in logger.handlers
        if isinstance(h, logging.FileHandler | logging.StreamHandler)
    )
    assert handler_count >= 2


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


def test_console_always_enabled(caplog: pytest.LogCaptureFixture) -> None:
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
        "guard_core.sync.utils.logging.FileHandler",
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
