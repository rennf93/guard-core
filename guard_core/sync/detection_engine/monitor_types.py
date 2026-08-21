from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

DEFAULT_RECENT_TIMES_WINDOW = 100


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
    recent_times: deque[float] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_RECENT_TIMES_WINDOW)
    )
    last_anomaly_emitted_at: float | None = None
