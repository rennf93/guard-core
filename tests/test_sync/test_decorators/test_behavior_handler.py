import logging
import time
from typing import Any, Literal, cast
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.redis_handler import redis_handler
from tests.test_sync.conftest import MockGuardResponse


class _BoundedReaderResponse:
    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self._status_code = status_code
        self._headers: dict[str, str] = {}
        self._body = body
        self.read_body_prefix_calls = 0
        self.body_property_accessed = False

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def body(self) -> bytes:
        self.body_property_accessed = True
        return self._body

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        return self._body[:max_bytes]


def test_behavior_rule_creation() -> None:
    rule = BehaviorRule(
        rule_type="usage",
        threshold=10,
    )
    assert rule.rule_type == "usage"
    assert rule.threshold == 10
    assert rule.window == 3600
    assert rule.pattern is None
    assert rule.action == "log"
    assert rule.custom_action is None

    custom_action = MagicMock()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=5,
        window=1800,
        pattern="json:status==success",
        action="ban",
        custom_action=custom_action,
    )
    assert rule.rule_type == "return_pattern"
    assert rule.threshold == 5
    assert rule.window == 1800
    assert rule.pattern == "json:status==success"
    assert rule.action == "ban"
    assert rule.custom_action == custom_action


@pytest.mark.parametrize(
    "rule_type,threshold,window,pattern,action",
    [
        ("usage", 10, 3600, None, "log"),
        ("return_pattern", 5, 1800, "status:200", "ban"),
        ("frequency", 20, 300, "regex:error", "throttle"),
    ],
)
def test_behavior_rule_parameterized(
    rule_type: Literal["usage", "return_pattern", "frequency"],
    threshold: int,
    window: int,
    pattern: str | None,
    action: Literal["ban", "log", "throttle", "alert"],
) -> None:
    rule = BehaviorRule(
        rule_type=rule_type,
        threshold=threshold,
        window=window,
        pattern=pattern,
        action=action,
    )
    assert rule.rule_type == rule_type
    assert rule.threshold == threshold
    assert rule.window == window
    assert rule.pattern == pattern
    assert rule.action == action


def test_behavior_tracker_initialization(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    assert tracker.config == security_config
    assert tracker.logger is not None
    assert tracker.usage_counts is not None
    assert tracker.return_patterns is not None
    assert tracker.redis_handler is None


def test_initialize_redis(security_config_redis: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()

    tracker.initialize_redis(redis_mgr)
    assert tracker.redis_handler == redis_mgr

    redis_mgr.close()


def test_track_endpoint_usage_in_memory(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=3, window=1)

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert len(tracker.usage_counts[endpoint_id][client_ip]) == 4


def test_track_endpoint_usage_with_window_cleanup(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=2, window=1)

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    current_time = time.time()
    old_time = current_time - 2
    tracker.usage_counts[endpoint_id][client_ip].append(old_time)
    tracker.usage_counts[endpoint_id][client_ip].append(old_time)

    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert len(tracker.usage_counts[endpoint_id][client_ip]) == 1


def test_track_endpoint_usage_with_redis(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=2, window=60)
    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    current_time = time.time()

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        mock_keys.return_value = [
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time}"
        ]
        mock_set_key.return_value = None
        result = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert not result

        mock_keys.return_value = [
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time}",
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time + 1}",
        ]
        result = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert not result

        mock_keys.return_value = [
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time}",
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time + 1}",
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time + 2}",
        ]
        result = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert result

    redis_mgr.close()


def test_track_return_pattern_no_pattern(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=5)

    response = MockGuardResponse("test", status_code=200)
    result = tracker.track_return_pattern("/api/test", "192.168.1.1", response, rule)
    assert not result


def test_track_return_pattern_in_memory(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=2, pattern="status:200")

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    response = MockGuardResponse("success", status_code=200)

    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    assert tracker.track_return_pattern(endpoint_id, client_ip, response, rule)


def test_track_return_pattern_with_redis(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="status:200")
    response = MockGuardResponse("success", status_code=200)
    current_time = time.time()

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        key = "behavior_returns:behavior:return:/api/test:192.168.1.1:status:200"
        mock_keys.return_value = [
            f"{key}:{current_time}",
            f"{key}:{current_time + 1}",
        ]
        mock_set_key.return_value = None

        result = tracker.track_return_pattern(
            "/api/test", "192.168.1.1", response, rule
        )
        assert result

    redis_mgr.close()


@pytest.mark.parametrize(
    "status_code,pattern,expected",
    [
        (200, "status:200", True),
        (404, "status:200", False),
    ],
)
def test_check_response_pattern(
    security_config: SecurityConfig,
    status_code: int,
    pattern: str,
    expected: bool,
) -> None:
    tracker = BehaviorTracker(security_config)

    response = MockGuardResponse("", status_code=status_code)

    result = tracker._check_response_pattern(response, pattern)
    assert result == expected


def test_check_response_pattern_json_invalid(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"invalid json {", status_code=200)

    result = tracker._check_response_pattern(response, "json:status==success")
    assert result is False


def test_check_response_pattern_no_body_when_body_scan_disabled(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"test pattern", status_code=200)

    result = tracker._check_response_pattern(response, "test pattern")

    assert result is None
    assert response.read_body_prefix_calls == 0


def test_check_response_pattern_empty_body_is_not_matched(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"", status_code=200)

    result = tracker._check_response_pattern(response, "test pattern")
    assert result is False


class _StreamingResponseWithoutBody:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code


def test_check_response_pattern_missing_bounded_reader_logs_once(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = cast(GuardResponse, _StreamingResponseWithoutBody())

    with patch.object(tracker.logger, "warning") as mock_warning:
        for _ in range(5):
            result = tracker._check_response_pattern(response, "attack-marker")

    assert result is None
    mock_warning.assert_called_once()
    assert "attack-marker" in mock_warning.call_args.args
    assert "could not be evaluated" in mock_warning.call_args.args[0]


def test_check_response_pattern_missing_bounded_reader_logs_per_pattern(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = cast(GuardResponse, _StreamingResponseWithoutBody())

    with patch.object(tracker.logger, "warning") as mock_warning:
        tracker._check_response_pattern(response, "pattern-one")
        tracker._check_response_pattern(response, "pattern-two")

    assert mock_warning.call_count == 2


def test_check_response_pattern_bytes_body(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"test content", status_code=200)

    result = tracker._check_response_pattern(response, "test content")
    assert result is True
    assert response.read_body_prefix_calls == 1


def test_check_response_pattern_json_match_via_bounded_reader(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b'{"status": "success"}', status_code=200)

    result = tracker._check_response_pattern(response, "json:status==success")
    assert result is True


def test_check_response_pattern_regex_match_via_bounded_reader(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(
        b"Error: Database connection failed", status_code=500
    )

    result = tracker._check_response_pattern(response, "regex:database.*failed")
    assert result is True


def test_check_response_pattern_never_reads_body_property(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"test content", status_code=200)

    tracker._check_response_pattern(response, "test content")

    assert response.body_property_accessed is False


def test_check_response_pattern_exception(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)

    with patch.object(tracker.logger, "error") as mock_logger:
        response = _BoundedReaderResponse(b"test", status_code=200)

        with patch("json.loads", side_effect=Exception("Test error")):
            result = tracker._check_response_pattern(response, "json:test==value")
            assert result is False
            mock_logger.assert_called_once()


def test_check_response_pattern_non_bytes_prefix_is_logged_and_not_matched(
    security_config: SecurityConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)

    class _StringReturningReader:
        status_code = 200
        headers: dict[str, str] = {}

        def read_body_prefix(self, max_bytes: int) -> bytes:
            return cast(bytes, "not bytes")

    response = cast(GuardResponse, _StringReturningReader())

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = tracker._check_response_pattern(response, "12345")

    assert result is None
    assert "return_pattern rule with pattern '12345' could not be evaluated" in (
        caplog.text
    )


def test_check_response_pattern_raising_bounded_reader_is_could_not_evaluate(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)

    class _RaisingReader:
        status_code = 200
        headers: dict[str, str] = {}

        def read_body_prefix(self, max_bytes: int) -> bytes:
            raise RuntimeError("stream closed")

    response = cast(GuardResponse, _RaisingReader())

    result = tracker._check_response_pattern(response, "attack")
    assert result is None


def test_check_response_pattern_oversized_prefix_is_capped(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    security_config.behavior_max_response_body_inspect_bytes = 1024

    class _OverReportingReader:
        status_code = 200
        headers: dict[str, str] = {}

        def __init__(self) -> None:
            self.requested_max_bytes: int | None = None

        def read_body_prefix(self, max_bytes: int) -> bytes:
            self.requested_max_bytes = max_bytes
            return b"A" * 2000 + b"MARKER"

    tracker = BehaviorTracker(security_config)
    response = _OverReportingReader()

    result = tracker._check_response_pattern(cast(GuardResponse, response), "MARKER")

    assert result is False
    assert response.requested_max_bytes == 1024


def test_match_json_pattern_exception(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)

    class ProblematicData:
        def __str__(self) -> str:
            raise Exception("Test exception in str conversion")

    problematic_data = {"nested": {"value": ProblematicData()}}

    result = tracker._match_json_pattern(problematic_data, "nested.value==test")
    assert not result


@pytest.mark.parametrize(
    "data,pattern,expected",
    [
        ({"status": "success"}, "status==success", True),
        ({"status": "error"}, "status==success", False),
        ({"result": {"status": "win"}}, "result.status==win", True),
        ({"result": {"status": "lose"}}, "result.status==win", False),
        ({"items": ["rare", "common"]}, "items[]==rare", True),
        ({"items": ["common", "uncommon"]}, "items[]==rare", False),
        ({"other": "value"}, "status==success", False),
        ({"result": {}}, "result.status==win", False),
    ],
)
def test_match_json_pattern(
    security_config: SecurityConfig, data: dict[str, Any], pattern: str, expected: bool
) -> None:
    tracker = BehaviorTracker(security_config)
    result = tracker._match_json_pattern(data, pattern)
    assert result == expected


def test_match_json_pattern_invalid(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)

    result = tracker._match_json_pattern({"status": "success"}, "status")
    assert not result

    result = tracker._match_json_pattern(
        {"status": "success"}, "invalid..pattern==test"
    )
    assert not result


def test_apply_action_custom(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    custom_action = MagicMock()
    rule = BehaviorRule(rule_type="usage", threshold=5, custom_action=custom_action)

    tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
    custom_action.assert_called_once_with("192.168.1.1", "/api/test", "Test violation")


def test_apply_action_ban(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "warning") as mock_logger,
    ):
        mock_ban_manager.ban_ip = MagicMock()

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_ban_manager.ban_ip.assert_called_once_with(
            "192.168.1.1", 3600, "behavioral_violation"
        )
        mock_logger.assert_called_once()


def test_apply_action_log(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with patch.object(tracker.logger, "warning") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "Behavioral anomaly detected: Test violation"
        )


def test_apply_action_throttle(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with patch.object(tracker.logger, "warning") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with("Throttling IP 192.168.1.1: Test violation")


def test_apply_action_alert(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")

    with patch.object(tracker.logger, "critical") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "ALERT - Behavioral anomaly: Test violation"
        )


def test_apply_action_log_respects_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = "ERROR"
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with patch.object(tracker.logger, "error") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "Behavioral anomaly detected: Test violation"
        )


def test_apply_action_ban_respects_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = "ERROR"
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "error") as mock_logger,
    ):
        mock_ban_manager.ban_ip = MagicMock()

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_logger.assert_called_once()


def test_apply_action_ban_silenced_when_log_suspicious_level_none(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "warning") as mock_warning,
    ):
        mock_ban_manager.ban_ip = MagicMock()

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_ban_manager.ban_ip.assert_called_once_with(
            "192.168.1.1", 3600, "behavioral_violation"
        )
        mock_warning.assert_not_called()


def test_apply_action_log_silenced_when_log_suspicious_level_none(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with (
        patch.object(tracker.logger, "warning") as mock_warning,
        patch.object(tracker.logger, "error") as mock_error,
    ):
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_warning.assert_not_called()
        mock_error.assert_not_called()


def test_apply_action_alert_ignores_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")

    with patch.object(tracker.logger, "critical") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "ALERT - Behavioral anomaly: Test violation"
        )


def test_passive_mode_log_respects_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True
    security_config.log_suspicious_level = "ERROR"
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with patch.object(tracker.logger, "error") as mock_logger:
        tracker._log_passive_mode_action(rule, "192.168.1.1", "Test details")
        mock_logger.assert_called_once_with(
            "[PASSIVE MODE] Would throttle IP 192.168.1.1: Test details"
        )


def test_passive_mode_log_silenced_when_log_suspicious_level_none(
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with (
        patch.object(tracker.logger, "warning") as mock_warning,
        patch.object(tracker.logger, "error") as mock_error,
    ):
        tracker._log_passive_mode_action(rule, "192.168.1.1", "Test details")
        mock_warning.assert_not_called()
        mock_error.assert_not_called()


def test_redis_key_timestamp_filtering(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=2, window=60)
    current_time = time.time()

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        mock_keys.return_value = [
            f"behavior_usage:test:key:{current_time}",
            f"behavior_usage:test:key:{current_time - 30}",
            f"behavior_usage:test:key:{current_time - 120}",
            "behavior_usage:test:key:invalid_timestamp",
            "behavior_usage:test:key:",
        ]
        mock_set_key.return_value = None

        result = tracker.track_endpoint_usage("/api/test", "192.168.1.1", rule)
        assert not result

    redis_mgr.close()


def test_track_return_pattern_no_match(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="status:404")

    response = MockGuardResponse("success", status_code=200)
    result = tracker.track_return_pattern("/api/test", "192.168.1.1", response, rule)
    assert not result


def test_track_return_pattern_window_cleanup(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=2, window=1, pattern="status:200"
    )

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    pattern_key = f"{endpoint_id}:{rule.pattern}"

    current_time = time.time()
    old_time = current_time - 2
    tracker.return_patterns[pattern_key][client_ip].extend([old_time, old_time])

    response = MockGuardResponse("success", status_code=200)

    result = tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert not result

    assert len(tracker.return_patterns[pattern_key][client_ip]) == 1


def test_redis_return_pattern_timestamp_filtering(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(
        rule_type="return_pattern", threshold=1, window=60, pattern="status:200"
    )
    current_time = time.time()
    response = MockGuardResponse("success", status_code=200)

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        mock_keys.return_value = [
            f"behavior_returns:test:key:{current_time}",
            f"behavior_returns:test:key:{current_time - 120}",
            "behavior_returns:test:key:invalid",
        ]
        mock_set_key.return_value = None

        result = tracker.track_return_pattern(
            "/api/test", "192.168.1.1", response, rule
        )
        assert not result

    redis_mgr.close()


def test_log_passive_mode_action_unknown_action_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker

    tracker = BehaviorTracker(SecurityConfig())
    rule = BehaviorRule(rule_type="usage", threshold=1, action="log")
    cast(Any, rule).action = "unknown"
    with caplog.at_level(logging.INFO):
        tracker._log_passive_mode_action(rule, "1.2.3.4", "details")
    unknown_logs = [r for r in caplog.records if "details" in r.getMessage()]
    assert not unknown_logs


def test_execute_active_mode_action_unknown_action_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker

    tracker = BehaviorTracker(SecurityConfig())
    rule = BehaviorRule(rule_type="usage", threshold=1, action="log")
    cast(Any, rule).action = "unknown"
    with caplog.at_level(logging.INFO):
        tracker._execute_active_mode_action(rule, "1.2.3.4", "ep", "details")
    unknown_logs = [r for r in caplog.records if "details" in r.getMessage()]
    assert not unknown_logs
