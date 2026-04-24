from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("guard_core")

try:
    import logfire

    _logfire_available = True
except ImportError:
    logfire = None  # type: ignore[assignment]
    _logfire_available = False


class LogfireHandler:
    def __init__(self, config: Any) -> None:
        self._config = config

    async def start(self) -> None:
        if not _logfire_available:
            logger.warning("logfire not installed, Logfire handler disabled")
            return
        logfire.configure(service_name=self._config.logfire_service_name)

    async def stop(self) -> None:
        pass

    async def send_event(self, event: Any) -> None:
        if not _logfire_available:
            return
        event_type = getattr(event, "event_type", "unknown")
        with logfire.span(
            f"guard.event.{event_type}",
            event_type=event_type,
            ip_address=getattr(event, "ip_address", ""),
            action_taken=getattr(event, "action_taken", ""),
            reason=getattr(event, "reason", ""),
            endpoint=getattr(event, "endpoint", ""),
            method=getattr(event, "method", ""),
            status_code=getattr(event, "status_code", 0),
        ):
            pass

    async def send_metric(self, metric: Any) -> None:
        if not _logfire_available:
            return
        metric_type = getattr(metric, "metric_type", "unknown")
        value = getattr(metric, "value", 0)
        endpoint = getattr(metric, "endpoint", "")
        tags = getattr(metric, "tags", {}) or {}
        safe_tags = {k: v for k, v in tags.items() if k not in ("value", "endpoint")}
        logfire.info(
            f"guard.metric.{metric_type}",
            value=value,
            endpoint=endpoint,
            **safe_tags,
        )

    async def initialize_redis(self, redis_handler: Any) -> None:
        pass

    async def flush_buffer(self) -> None:
        pass

    async def get_dynamic_rules(self) -> Any | None:
        return None

    async def health_check(self) -> bool:
        return _logfire_available
