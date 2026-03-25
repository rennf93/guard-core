import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean, stdev
from typing import Any


@dataclass
class PerformanceMetric:
    pattern: str
    execution_time: float
    content_length: int
    timestamp: datetime
    matched: bool
    timeout: bool = False


@dataclass
class PatternStats:
    pattern: str
    total_executions: int = 0
    total_matches: int = 0
    total_timeouts: int = 0
    avg_execution_time: float = 0.0
    max_execution_time: float = 0.0
    min_execution_time: float = float("inf")
    recent_times: deque[float] = field(default_factory=lambda: deque(maxlen=100))


class PerformanceMonitor:
    def __init__(
        self,
        anomaly_threshold: float = 3.0,
        slow_pattern_threshold: float = 0.1,
        history_size: int = 1000,
        max_tracked_patterns: int = 1000,
    ):
        self.anomaly_threshold = max(1.0, min(10.0, float(anomaly_threshold)))
        self.slow_pattern_threshold = max(
            0.01, min(10.0, float(slow_pattern_threshold))
        )
        self.history_size = max(100, min(10000, int(history_size)))
        self.max_tracked_patterns = max(100, min(5000, int(max_tracked_patterns)))

        self.pattern_stats: dict[str, PatternStats] = {}
        self.recent_metrics: deque[PerformanceMetric] = deque(maxlen=history_size)
        self.anomaly_callbacks: list[Any] = []
        self._lock = threading.Lock()

    def record_metric(
        self,
        pattern: str,
        execution_time: float,
        content_length: int,
        matched: bool,
        timeout: bool = False,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ) -> None:
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        execution_time = max(0.0, float(execution_time))
        content_length = max(0, int(content_length))

        metric = PerformanceMetric(
            pattern=pattern,
            execution_time=execution_time,
            content_length=content_length,
            timestamp=datetime.now(timezone.utc),
            matched=matched,
            timeout=timeout,
        )

        with self._lock:
            self.recent_metrics.append(metric)

            if pattern not in self.pattern_stats:
                if len(self.pattern_stats) >= self.max_tracked_patterns:
                    oldest_pattern = next(iter(self.pattern_stats))
                    del self.pattern_stats[oldest_pattern]
                self.pattern_stats[pattern] = PatternStats(pattern=pattern)

            stats = self.pattern_stats[pattern]
            stats.total_executions += 1
            if matched:
                stats.total_matches += 1
            if timeout:
                stats.total_timeouts += 1

            if not timeout:
                stats.recent_times.append(execution_time)
                stats.max_execution_time = max(stats.max_execution_time, execution_time)
                stats.min_execution_time = min(stats.min_execution_time, execution_time)
                if stats.recent_times:
                    stats.avg_execution_time = mean(stats.recent_times)

        self._check_anomalies(metric, agent_handler, correlation_id)

    def _detect_timeout_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, Any] | None:
        if metric.timeout:
            return {
                "type": "timeout",
                "pattern": metric.pattern,
                "content_length": metric.content_length,
            }
        return None

    def _detect_slow_execution_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, Any] | None:
        if not metric.timeout and metric.execution_time > self.slow_pattern_threshold:
            return {
                "type": "slow_execution",
                "pattern": metric.pattern,
                "execution_time": metric.execution_time,
                "content_length": metric.content_length,
            }
        return None

    def _detect_statistical_anomaly(
        self, metric: PerformanceMetric
    ) -> dict[str, Any] | None:
        stats = self.pattern_stats.get(metric.pattern)
        if not stats or len(stats.recent_times) < 10:
            return None

        recent_times = list(stats.recent_times)
        if len(recent_times) <= 1:
            return None  # pragma: no cover

        avg_time = mean(recent_times)
        std_time = stdev(recent_times)

        if std_time <= 0:
            return None

        z_score = (metric.execution_time - avg_time) / std_time
        if abs(z_score) > self.anomaly_threshold:
            return {
                "type": "statistical_anomaly",
                "pattern": metric.pattern,
                "execution_time": metric.execution_time,
                "z_score": z_score,
                "avg_time": avg_time,
                "std_time": std_time,
            }
        return None

    def _send_anomaly_event(
        self,
        anomaly: dict[str, Any],
        agent_handler: Any,
        correlation_id: str | None,
    ) -> None:
        try:
            event_data = {
                "timestamp": datetime.now(timezone.utc),
                "event_type": f"pattern_anomaly_{anomaly['type']}",
                "ip_address": "system",
                "action_taken": "anomaly_detected",
                "reason": f"Pattern performance anomaly: {anomaly['type']}",
                "metadata": {
                    "component": "PerformanceMonitor",
                    "correlation_id": correlation_id,
                    **anomaly,
                },
            }
            event = type("SecurityEvent", (), event_data)()
            agent_handler.send_event(event)
        except Exception:
            pass

    def _sanitize_anomaly_data(self, anomaly: dict[str, Any]) -> dict[str, Any]:
        safe_anomaly = anomaly.copy()
        if "pattern" in safe_anomaly:
            pattern = str(safe_anomaly["pattern"])
            safe_anomaly["pattern"] = (
                pattern[:50] + "..." if len(pattern) > 50 else pattern
            )
            safe_anomaly["pattern_hash"] = str(hash(pattern))[:8]
        return safe_anomaly

    def _send_callback_error_event(
        self,
        error: Exception,
        safe_anomaly: dict[str, Any],
        agent_handler: Any,
        correlation_id: str | None,
    ) -> None:
        try:
            event_data = {
                "timestamp": datetime.now(timezone.utc),
                "event_type": "detection_engine_callback_error",
                "ip_address": "system",
                "action_taken": "logged",
                "reason": f"Anomaly callback failed: {str(error)}",
                "metadata": {
                    "component": "PerformanceMonitor",
                    "correlation_id": correlation_id,
                    "callback_error": str(error),
                    "anomaly_type": safe_anomaly.get("type", "unknown"),
                },
            }
            event = type("SecurityEvent", (), event_data)()
            agent_handler.send_event(event)
        except Exception:
            pass

    def _notify_callbacks(
        self,
        anomaly: dict[str, Any],
        agent_handler: Any,
        correlation_id: str | None,
    ) -> None:
        safe_anomaly = self._sanitize_anomaly_data(anomaly)

        for callback in self.anomaly_callbacks:
            try:
                callback(safe_anomaly)
            except Exception as e:
                if agent_handler:
                    self._send_callback_error_event(
                        e, safe_anomaly, agent_handler, correlation_id
                    )

    def _check_anomalies(
        self,
        metric: PerformanceMetric,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ) -> None:
        anomalies: list[dict[str, Any]] = []

        timeout_anomaly = self._detect_timeout_anomaly(metric)
        if timeout_anomaly:
            anomalies.append(timeout_anomaly)
        else:
            slow_anomaly = self._detect_slow_execution_anomaly(metric)
            if slow_anomaly:
                anomalies.append(slow_anomaly)

        statistical_anomaly = self._detect_statistical_anomaly(metric)
        if statistical_anomaly:
            anomalies.append(statistical_anomaly)

        if agent_handler:
            for anomaly in anomalies:
                self._send_anomaly_event(anomaly, agent_handler, correlation_id)

        for anomaly in anomalies:
            self._notify_callbacks(anomaly, agent_handler, correlation_id)

    def get_pattern_report(self, pattern: str) -> dict[str, Any] | None:
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        stats = self.pattern_stats.get(pattern)
        if not stats:
            return None

        safe_pattern = pattern[:50] + "..." if len(pattern) > 50 else pattern

        return {
            "pattern": safe_pattern,
            "pattern_hash": str(hash(pattern))[:8],
            "total_executions": stats.total_executions,
            "total_matches": stats.total_matches,
            "total_timeouts": stats.total_timeouts,
            "match_rate": stats.total_matches / max(stats.total_executions, 1),
            "timeout_rate": stats.total_timeouts / max(stats.total_executions, 1),
            "avg_execution_time": round(stats.avg_execution_time, 4),
            "max_execution_time": round(stats.max_execution_time, 4),
            "min_execution_time": round(
                stats.min_execution_time
                if stats.min_execution_time != float("inf")
                else 0.0,
                4,
            ),
        }

    def get_slow_patterns(self, limit: int = 10) -> list[dict[str, Any]]:
        patterns_with_times = [
            (stats.avg_execution_time, pattern)
            for pattern, stats in self.pattern_stats.items()
            if stats.recent_times
        ]

        patterns_with_times.sort(reverse=True)

        reports = []
        for _, pattern in patterns_with_times[:limit]:
            report = self.get_pattern_report(pattern)
            if report is not None:
                reports.append(report)
        return reports

    def get_problematic_patterns(self) -> list[dict[str, Any]]:
        problematic = []

        for pattern, stats in self.pattern_stats.items():
            if stats.total_executions == 0:
                continue

            timeout_rate = stats.total_timeouts / stats.total_executions

            if timeout_rate > 0.1:
                report = self.get_pattern_report(pattern)
                if report:
                    report["issue"] = "high_timeout_rate"
                    problematic.append(report)

            elif stats.avg_execution_time > self.slow_pattern_threshold:
                report = self.get_pattern_report(pattern)
                if report:
                    report["issue"] = "consistently_slow"
                    problematic.append(report)

        return problematic

    def _get_empty_summary(self) -> dict[str, Any]:
        return {
            "total_executions": 0,
            "avg_execution_time": 0.0,
            "timeout_rate": 0.0,
            "match_rate": 0.0,
        }

    def _extract_metric_components(
        self,
    ) -> tuple[list[float], int, int]:
        recent_times = [m.execution_time for m in self.recent_metrics if not m.timeout]
        timeouts = sum(1 for m in self.recent_metrics if m.timeout)
        matches = sum(1 for m in self.recent_metrics if m.matched)
        return recent_times, timeouts, matches

    def _build_summary_dict(
        self,
        recent_times: list[float],
        timeouts: int,
        matches: int,
    ) -> dict[str, Any]:
        total_metrics = len(self.recent_metrics)
        return {
            "total_executions": total_metrics,
            "avg_execution_time": mean(recent_times) if recent_times else 0.0,
            "max_execution_time": max(recent_times) if recent_times else 0.0,
            "min_execution_time": min(recent_times) if recent_times else 0.0,
            "timeout_rate": timeouts / total_metrics,
            "match_rate": matches / total_metrics,
            "total_patterns": len(self.pattern_stats),
        }

    def get_summary_stats(self) -> dict[str, Any]:
        if not self.recent_metrics:
            return self._get_empty_summary()

        recent_times, timeouts, matches = self._extract_metric_components()
        return self._build_summary_dict(recent_times, timeouts, matches)

    def register_anomaly_callback(self, callback: Any) -> None:
        self.anomaly_callbacks.append(callback)

    def clear_stats(self) -> None:
        with self._lock:
            self.pattern_stats.clear()
            self.recent_metrics.clear()

    def remove_pattern_stats(self, pattern: str) -> None:
        with self._lock:
            if pattern in self.pattern_stats:
                del self.pattern_stats[pattern]
