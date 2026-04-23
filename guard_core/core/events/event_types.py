from __future__ import annotations

from dataclasses import dataclass

EVENT_PENETRATION_ATTEMPT = "penetration_attempt"
EVENT_IP_BLOCKED = "ip_blocked"
EVENT_IP_BANNED = "ip_banned"
EVENT_IP_UNBANNED = "ip_unbanned"
EVENT_CLOUD_BLOCKED = "cloud_blocked"
EVENT_HTTPS_ENFORCED = "https_enforced"
EVENT_DECORATOR_VIOLATION = "decorator_violation"
EVENT_BEHAVIOR_VIOLATION = "behavior_violation"
EVENT_PATTERN_DETECTED = "pattern_detected"
EVENT_DYNAMIC_RULE_UPDATED = "dynamic_rule_updated"
EVENT_DYNAMIC_RULE_APPLIED = "dynamic_rule_applied"
EVENT_EMERGENCY_MODE = "emergency_mode_activated"

EVENT_TYPE_VALUES: frozenset[str] = frozenset({
    EVENT_PENETRATION_ATTEMPT,
    EVENT_IP_BLOCKED,
    EVENT_IP_BANNED,
    EVENT_IP_UNBANNED,
    EVENT_CLOUD_BLOCKED,
    EVENT_HTTPS_ENFORCED,
    EVENT_DECORATOR_VIOLATION,
    EVENT_BEHAVIOR_VIOLATION,
    EVENT_PATTERN_DETECTED,
    EVENT_DYNAMIC_RULE_UPDATED,
    EVENT_DYNAMIC_RULE_APPLIED,
    EVENT_EMERGENCY_MODE,
})

METRIC_RESPONSE_TIME = "response_time"
METRIC_REQUEST_COUNT = "request_count"
METRIC_ERROR_RATE = "error_rate"

METRIC_TYPE_VALUES: frozenset[str] = frozenset({
    METRIC_RESPONSE_TIME,
    METRIC_REQUEST_COUNT,
    METRIC_ERROR_RATE,
})


@dataclass(frozen=True)
class EventFilter:
    muted_event_types: frozenset[str] = frozenset()
    muted_metric_types: frozenset[str] = frozenset()

    def is_event_allowed(self, event_type: str) -> bool:
        return event_type not in self.muted_event_types

    def is_metric_allowed(self, metric_type: str) -> bool:
        return metric_type not in self.muted_metric_types