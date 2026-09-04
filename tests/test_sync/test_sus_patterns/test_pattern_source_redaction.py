import concurrent.futures
import re
import time
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync._utils.detection_scan import _fallback_pattern_check
from guard_core.sync.detection_engine.monitor import PerformanceMonitor
from guard_core.sync.detection_engine.monitor_anomalies import (
    build_anomaly_event_data,
    sanitize_anomaly_data,
)
from guard_core.sync.detection_engine.monitor_reporting import build_pattern_report
from guard_core.sync.detection_engine.monitor_types import PatternStats
from guard_core.sync.handlers import suspatterns_handler as sph
from guard_core.sync.handlers._dynamic_rule_application import (
    DynamicRuleApplicationMixin,
)
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_SECRET_PATTERN = r"password=hunter2SuperSecretValue"


@pytest.fixture
def fresh_legacy_singleton() -> Iterator[SusPatternsManager]:
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    saved_global = sph.sus_patterns_handler

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    legacy = SusPatternsManager()
    sph.sus_patterns_handler = legacy

    yield legacy

    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config
    sph.sus_patterns_handler = saved_global


def test_check_regex_pattern_timeout_log_redacts_secret_shaped_custom_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager.configure(SecurityConfig(detection_compiler_timeout=0.1))
    ok = manager.add_pattern(_SECRET_PATTERN, custom=True)
    assert ok

    compiled = re.compile(_SECRET_PATTERN, re.IGNORECASE | re.MULTILINE)
    fake_pattern_start = time.monotonic() - 1000.0

    with patch("guard_core.sync.handlers._suspatterns_regex.logger") as mock_logger:
        threat, timed_out = manager._check_regex_pattern(
            compiled, "unrelated content", "203.0.113.5", fake_pattern_start, "custom"
        )

    assert threat is None
    assert timed_out is True
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_check_regex_pattern_timeout_log_leaves_builtin_pattern_unchanged(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager.configure(SecurityConfig(detection_compiler_timeout=0.1))
    builtin_source = r"[a-z]+attackterm[a-z]+"
    compiled = re.compile(builtin_source)
    fake_pattern_start = time.monotonic() - 1000.0

    with patch("guard_core.sync.handlers._suspatterns_regex.logger") as mock_logger:
        manager._check_regex_pattern(
            compiled, "unrelated content", "203.0.113.5", fake_pattern_start, "custom"
        )

    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert builtin_source[:50] in logged
    assert "[REDACTED]" not in logged


def test_check_windowed_pattern_timeout_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton

    def _finder(_content: str) -> Iterator[re.Match[str]]:
        yield from ()

    pattern = re.compile(_SECRET_PATTERN)
    with patch(
        "guard_core.sync.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.sync.handlers._suspatterns_regex.logger") as mock_logger:
            threat, timed_out = manager._check_windowed_pattern(
                pattern, _finder, "content", time.monotonic(), "custom", "unknown"
            )

    assert threat is None
    assert timed_out is True
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_check_windowed_pattern_exception_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton

    def _finder(_content: str) -> Iterator[re.Match[str]]:
        yield from ()

    pattern = re.compile(_SECRET_PATTERN)
    with patch(
        "guard_core.sync.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("boom")
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.sync.handlers._suspatterns_regex.logger") as mock_logger:
            threat, timed_out = manager._check_windowed_pattern(
                pattern, _finder, "content", time.monotonic(), "custom", "unknown"
            )

    assert threat is None
    assert timed_out is False
    logged = " ".join(str(call) for call in mock_logger.error.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_check_pattern_with_timeout_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager._config = MagicMock(detection_compiler_timeout=0.1)
    pattern = re.compile(_SECRET_PATTERN)

    with patch(
        "guard_core.sync.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.sync.handlers._suspatterns_regex.logger") as mock_logger:
            match, timed_out = manager._check_pattern_with_timeout(
                pattern, "content", "203.0.113.5", 0.0
            )

    assert match is None
    assert timed_out is True
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_check_pattern_with_timeout_exception_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager._config = MagicMock(detection_compiler_timeout=0.1)
    pattern = re.compile(_SECRET_PATTERN)

    with patch(
        "guard_core.sync.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("boom")
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.sync.handlers._suspatterns_regex.logger") as mock_logger:
            match, timed_out = manager._check_pattern_with_timeout(
                pattern, "content", "203.0.113.5", 0.0
            )

    assert match is None
    assert timed_out is False
    logged = " ".join(str(call) for call in mock_logger.error.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_detect_pattern_match_returns_redacted_pattern_label(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager._config = SecurityConfig()
    ok = manager.add_pattern(_SECRET_PATTERN, custom=True)
    assert ok

    is_threat, pattern_label = manager.detect_pattern_match(
        _SECRET_PATTERN, "203.0.113.9", context="request_body"
    )

    assert is_threat is True
    assert pattern_label is not None
    assert "hunter2" not in pattern_label
    assert "[REDACTED]" in pattern_label


def test_add_pattern_rejects_unsafe_pattern_without_leaking_secret_in_log(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    unsafe_pattern = "(unterminated[" + _SECRET_PATTERN

    with patch("guard_core.sync.handlers._suspatterns_registry.logger") as mock_logger:
        ok = manager.add_pattern(unsafe_pattern, custom=True)

    assert ok is False
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_dynamic_rule_apply_pattern_rules_logs_redact_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    class _Applier(DynamicRuleApplicationMixin):
        def __init__(self) -> None:
            import logging

            self.config = SecurityConfig()
            self.agent_handler = None
            self.logger = logging.getLogger(
                "guard_core.sync.handlers.dynamic_rule_test_pattern_redaction"
            )

    applier = _Applier()
    rules = DynamicRules(
        rule_id="r1",
        version=1,
        timestamp="2026-09-04T00:00:00Z",
        suspicious_patterns=[_SECRET_PATTERN, "(unterminated["],
    )

    with patch.object(applier, "logger") as mock_logger:
        applier._apply_pattern_rules(rules.suspicious_patterns)

    logged = " ".join(
        str(call)
        for call in (
            mock_logger.info.call_args_list + mock_logger.warning.call_args_list
        )
    )
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_anomaly_event_to_agent_redacts_secret_shaped_pattern() -> None:
    monitor = PerformanceMonitor()
    agent = MagicMock()
    agent.send_event = MagicMock()

    monitor.record_metric(
        pattern=_SECRET_PATTERN,
        execution_time=2.5,
        content_length=100,
        matched=False,
        timeout=True,
        agent_handler=agent,
        correlation_id="corr-1",
    )

    assert agent.send_event.call_count >= 1
    for call in agent.send_event.await_args_list:
        event = call.args[0]
        metadata = getattr(event, "metadata", {})
        assert "hunter2" not in str(metadata.get("pattern", ""))
        assert "[REDACTED]" in str(metadata.get("pattern", ""))


def test_build_anomaly_event_data_redacts_secret_shaped_pattern() -> None:
    anomaly = {"type": "timeout", "pattern": _SECRET_PATTERN, "content_length": 10}
    event_data = build_anomaly_event_data(anomaly, "corr-1")
    assert "hunter2" not in str(event_data["metadata"]["pattern"])
    assert event_data["metadata"]["pattern"] == "password=[REDACTED]"


def test_build_anomaly_event_data_without_pattern_key() -> None:
    anomaly = {"type": "timeout"}
    event_data = build_anomaly_event_data(anomaly, "corr-1")
    assert "pattern" not in event_data["metadata"]


def test_sanitize_anomaly_data_redacts_secret_shaped_pattern() -> None:
    anomaly = {"type": "timeout", "pattern": _SECRET_PATTERN}
    safe = sanitize_anomaly_data(anomaly)
    assert "hunter2" not in safe["pattern"]
    assert safe["pattern"] == "password=[REDACTED]"


def test_build_pattern_report_redacts_secret_shaped_pattern() -> None:
    stats = PatternStats(
        pattern=_SECRET_PATTERN,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    report = build_pattern_report(_SECRET_PATTERN, stats)
    assert "hunter2" not in report["pattern"]
    assert "[REDACTED]" in report["pattern"]


def test_build_pattern_report_leaves_builtin_pattern_unchanged() -> None:
    builtin_source = "test_pattern"
    stats = PatternStats(
        pattern=builtin_source,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    report = build_pattern_report(builtin_source, stats)
    assert report["pattern"] == builtin_source


def test_dynamic_rule_apply_user_agent_rules_logs_redact_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    class _Applier(DynamicRuleApplicationMixin):
        def __init__(self) -> None:
            import logging

            self.config = SecurityConfig()
            self.agent_handler = None
            self.logger = logging.getLogger(
                "guard_core.sync.handlers.dynamic_rule_test_user_agent_redaction"
            )

    applier = _Applier()
    with patch.object(applier, "logger") as mock_logger:
        applier._apply_user_agent_rules(
            [_SECRET_PATTERN, "(a+)+" + _SECRET_PATTERN + "$"]
        )

    assert mock_logger.warning.called
    logged = " ".join(
        str(call)
        for call in (
            mock_logger.info.call_args_list + mock_logger.warning.call_args_list
        )
    )
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_fallback_pattern_check_recursion_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager.configure(SecurityConfig())
    ok = manager.add_pattern(_SECRET_PATTERN, custom=True)
    assert ok

    def raising(
        pattern: re.Pattern[str],
        value: str,
        client_ip: str,
        pattern_start: float,
        category: str,
        context: str = "unknown",
    ) -> tuple[None, bool]:
        raise RecursionError("simulated regex recursion")

    with (
        patch.object(manager, "_check_regex_pattern", raising),
        patch("guard_core.sync._utils.detection_scan.logger") as mock_logger,
    ):
        detected, _ = _fallback_pattern_check(
            "probe value", "203.0.113.9", "request_body"
        )

    assert detected is False
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged
