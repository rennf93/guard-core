from collections import deque
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

from guard_core.sync.detection_engine.monitor import (
    PatternStats,
    PerformanceMetric,
    PerformanceMonitor,
)


def test_initialization() -> None:
    monitor = PerformanceMonitor()
    assert monitor.anomaly_threshold == 3.0
    assert monitor.slow_pattern_threshold == 0.1
    assert monitor.history_size == 1000
    assert monitor.max_tracked_patterns == 1000
    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0
    assert len(monitor.anomaly_callbacks) == 0

    monitor = PerformanceMonitor(
        anomaly_threshold=5.0,
        slow_pattern_threshold=0.5,
        history_size=500,
        max_tracked_patterns=200,
    )
    assert monitor.anomaly_threshold == 5.0
    assert monitor.slow_pattern_threshold == 0.5
    assert monitor.history_size == 500
    assert monitor.max_tracked_patterns == 200


def test_initialization_bounds() -> None:
    monitor = PerformanceMonitor(
        anomaly_threshold=0.5,
        slow_pattern_threshold=0.001,
        history_size=50,
        max_tracked_patterns=50,
    )
    assert monitor.anomaly_threshold == 1.0
    assert monitor.slow_pattern_threshold == 0.01
    assert monitor.history_size == 100
    assert monitor.max_tracked_patterns == 100

    monitor = PerformanceMonitor(
        anomaly_threshold=20.0,
        slow_pattern_threshold=20.0,
        history_size=20000,
        max_tracked_patterns=10000,
    )
    assert monitor.anomaly_threshold == 10.0
    assert monitor.slow_pattern_threshold == 10.0
    assert monitor.history_size == 10000
    assert monitor.max_tracked_patterns == 5000


def test_record_metric_pattern_truncation() -> None:
    monitor = PerformanceMonitor()

    long_pattern = "a" * 150
    monitor.record_metric(
        pattern=long_pattern,
        execution_time=0.05,
        content_length=100,
        matched=True,
    )

    stored_pattern = list(monitor.pattern_stats.keys())[0]
    assert len(stored_pattern) == 114
    assert stored_pattern.endswith("...[truncated]")


def test_record_metric_max_patterns_limit() -> None:
    monitor = PerformanceMonitor(max_tracked_patterns=100)

    patterns = [f"pattern_{i:03d}" for i in range(100)]
    for pattern in patterns:
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(monitor.pattern_stats) == 100

    monitor.record_metric(
        pattern="pattern_100",
        execution_time=0.01,
        content_length=100,
        matched=False,
    )

    assert len(monitor.pattern_stats) == 100

    assert "pattern_000" not in monitor.pattern_stats
    assert "pattern_100" in monitor.pattern_stats


def test_record_metric_with_timeout() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric(
        pattern="timeout_pattern",
        execution_time=1.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    stats = monitor.pattern_stats["timeout_pattern"]
    assert stats.total_executions == 1
    assert stats.total_timeouts == 1
    assert stats.total_matches == 0
    assert len(stats.recent_times) == 0


def test_check_anomalies_timeout() -> None:
    monitor = PerformanceMonitor()

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    monitor.record_metric(
        pattern="timeout_test",
        execution_time=5.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "timeout"
    assert "timeout_test" in anomalies_detected[0]["pattern"]


def test_check_anomalies_statistical() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "stat_pattern"
    for _ in range(20):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    anomalies_detected.clear()

    monitor.record_metric(
        pattern=pattern,
        execution_time=0.1,
        content_length=100,
        matched=False,
    )

    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "statistical_anomaly"
    assert anomalies_detected[0]["z_score"] > 2.0


def test_statistical_anomaly_insufficient_data() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "insufficient_pattern"
    for _ in range(8):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(anomalies_detected) == 0


def test_statistical_anomaly_zero_std_dev() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    pattern = "zero_std_pattern"
    for _ in range(15):
        monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    assert len(anomalies_detected) == 0


def test_statistical_anomaly_single_data_point() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    pattern = "single_point_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times.append(0.01)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = monitor._detect_statistical_anomaly(metric)

    assert result is None


def test_statistical_anomaly_within_threshold() -> None:
    monitor = PerformanceMonitor(anomaly_threshold=3.0)

    pattern = "within_threshold_pattern"
    stats = PatternStats(pattern=pattern)

    times = [
        0.008,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
    ]
    stats.recent_times = deque(times, maxlen=100)
    monitor.pattern_stats[pattern] = stats

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.012,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    result = monitor._detect_statistical_anomaly(metric)

    assert result is None


def test_check_anomalies_with_agent() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )

    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "pattern_anomaly_slow_execution"
    assert event.action_taken == "anomaly_detected"
    assert event.metadata["correlation_id"] == "test-123"


def test_check_anomalies_agent_error() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock(side_effect=Exception("Agent error"))

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


def test_anomaly_callback_error() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    def failing_callback(anomaly: dict[str, Any]) -> None:
        raise Exception("Callback error")

    monitor.register_anomaly_callback(failing_callback)

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-456",
    )

    assert agent_handler.send_event.call_count == 2
    error_event = agent_handler.send_event.call_args_list[1][0][0]
    assert error_event.event_type == "detection_engine_callback_error"
    assert "Callback error" in error_event.reason


def test_anomaly_callback_error_agent_failure() -> None:
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock(side_effect=Exception("Agent error"))

    def failing_callback(anomaly: dict[str, Any]) -> None:
        raise Exception("Callback error")

    monitor.register_anomaly_callback(failing_callback)

    monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


def test_get_pattern_report_not_found() -> None:
    monitor = PerformanceMonitor()

    report = monitor.get_pattern_report("non_existent")
    assert report is None


def test_get_pattern_report_truncation() -> None:
    monitor = PerformanceMonitor()

    pattern = "test_pattern"
    stats = PatternStats(
        pattern=pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[pattern] = stats

    report = monitor.get_pattern_report(pattern)
    assert report is not None
    assert report["pattern"] == pattern
    assert report["total_executions"] == 10
    assert report["match_rate"] == 0.5
    assert report["timeout_rate"] == 0.1


def test_get_pattern_report_long_pattern_truncation() -> None:
    monitor = PerformanceMonitor()

    stored_pattern = "a" * 100 + "...[truncated]"
    stats = PatternStats(
        pattern=stored_pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[stored_pattern] = stats

    long_original_pattern = "a" * 150
    report = monitor.get_pattern_report(long_original_pattern)

    assert report is not None
    assert report["total_executions"] == 10


def test_get_problematic_patterns_empty_stats() -> None:
    monitor = PerformanceMonitor()

    stats = PatternStats(pattern="empty_pattern")
    monitor.pattern_stats["empty_pattern"] = stats

    problematic = monitor.get_problematic_patterns()
    assert len(problematic) == 0


def test_get_problematic_patterns_high_timeout() -> None:
    monitor = PerformanceMonitor()

    for i in range(3):
        pattern = f"pattern_{i}"
        timeout_rate = 0.2 if i == 1 else 0.05

        for j in range(10):
            monitor.record_metric(
                pattern=pattern,
                execution_time=0.05,
                content_length=100,
                matched=False,
                timeout=(j < timeout_rate * 10),
            )

    problematic = monitor.get_problematic_patterns()

    assert len(problematic) == 1
    assert "pattern_1" in problematic[0]["pattern"]
    assert problematic[0]["issue"] == "high_timeout_rate"


def test_get_problematic_patterns_slow() -> None:
    monitor = PerformanceMonitor(slow_pattern_threshold=0.1)

    patterns = [
        ("fast_pattern", 0.05),
        ("slow_pattern", 0.2),
        ("very_slow_pattern", 0.5),
    ]

    for pattern, exec_time in patterns:
        for _ in range(5):
            monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    problematic = monitor.get_problematic_patterns()

    assert len(problematic) == 2
    problematic_patterns = [p["pattern"] for p in problematic]
    assert any("slow_pattern" in p for p in problematic_patterns)
    assert any("very_slow_pattern" in p for p in problematic_patterns)
    assert all(p["issue"] == "consistently_slow" for p in problematic)


def test_get_summary_stats_empty() -> None:
    monitor = PerformanceMonitor()

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 0
    assert stats["avg_execution_time"] == 0.0
    assert stats["timeout_rate"] == 0.0
    assert stats["match_rate"] == 0.0


def test_get_summary_stats_with_data() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("p1", 0.01, 100, True, False)
    monitor.record_metric("p2", 0.02, 200, False, False)
    monitor.record_metric("p3", 1.0, 300, False, True)
    monitor.record_metric("p4", 0.03, 400, True, False)

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 4
    assert stats["match_rate"] == 0.5
    assert stats["timeout_rate"] == 0.25
    assert stats["total_patterns"] == 4


def test_register_anomaly_callback() -> None:
    monitor = PerformanceMonitor()

    def callback(anomaly: dict[str, Any]) -> None:
        pass  # pragma: no cover

    monitor.register_anomaly_callback(callback)
    assert len(monitor.anomaly_callbacks) == 1
    assert monitor.anomaly_callbacks[0] == callback


def test_clear_stats() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("pattern1", 0.01, 100, True)
    monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2
    assert len(monitor.recent_metrics) == 2

    monitor.clear_stats()

    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0


def test_remove_pattern_stats() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric("pattern1", 0.01, 100, True)
    monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2

    monitor.remove_pattern_stats("pattern1")

    assert len(monitor.pattern_stats) == 1
    assert "pattern1" not in monitor.pattern_stats
    assert "pattern2" in monitor.pattern_stats

    monitor.remove_pattern_stats("non_existent")


def test_get_slow_patterns() -> None:
    monitor = PerformanceMonitor()

    patterns = [
        ("very_slow", 0.5),
        ("slow", 0.2),
        ("medium", 0.1),
        ("fast", 0.01),
        ("very_fast", 0.001),
    ]

    for pattern, exec_time in patterns:
        for _ in range(3):
            monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    slow_patterns = monitor.get_slow_patterns(limit=3)

    assert len(slow_patterns) == 3
    assert "very_slow" in slow_patterns[0]["pattern"]
    assert "slow" in slow_patterns[1]["pattern"]
    assert "medium" in slow_patterns[2]["pattern"]


def test_metric_validation() -> None:
    monitor = PerformanceMonitor()

    monitor.record_metric(
        pattern="test",
        execution_time=-1.0,
        content_length=-100,
        matched=False,
    )

    metric = monitor.recent_metrics[0]
    assert metric.execution_time == 0.0
    assert metric.content_length == 0


def test_pattern_stats_dataclass() -> None:
    stats = PatternStats(pattern="test_pattern")

    assert stats.pattern == "test_pattern"
    assert stats.total_executions == 0
    assert stats.total_matches == 0
    assert stats.total_timeouts == 0
    assert stats.avg_execution_time == 0.0
    assert stats.max_execution_time == 0.0
    assert stats.min_execution_time == float("inf")
    assert isinstance(stats.recent_times, deque)
    assert stats.recent_times.maxlen == 100


def test_performance_metric_dataclass() -> None:
    now = datetime.now(timezone.utc)
    metric = PerformanceMetric(
        pattern="test_pattern",
        execution_time=0.05,
        content_length=1000,
        timestamp=now,
        matched=True,
        timeout=False,
    )

    assert metric.pattern == "test_pattern"
    assert metric.execution_time == 0.05
    assert metric.content_length == 1000
    assert metric.timestamp == now
    assert metric.matched is True
    assert metric.timeout is False


def test_concurrent_access() -> None:
    monitor = PerformanceMonitor()

    def record_metrics(pattern: str, count: int) -> None:
        for i in range(count):
            monitor.record_metric(
                pattern=f"{pattern}_{i % 3}",
                execution_time=0.01 * (i % 5 + 1),
                content_length=100 * (i % 3 + 1),
                matched=i % 2 == 0,
            )

    record_metrics("task1", 10)
    record_metrics("task2", 10)
    record_metrics("task3", 10)

    assert len(monitor.recent_metrics) == 30
    total_patterns = len(monitor.pattern_stats)
    assert total_patterns > 0

    for _, stats in monitor.pattern_stats.items():
        assert stats.total_executions > 0
        assert stats.max_execution_time >= stats.min_execution_time
        if stats.recent_times:
            assert stats.avg_execution_time > 0
