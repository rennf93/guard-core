from __future__ import annotations

import logging
from typing import Any

from guard_core.core.events.event_types import EventFilter

logger = logging.getLogger("guard_core")


class CompositeAgentHandler:
    def __init__(
        self,
        handlers: list[Any],
        event_filter: EventFilter | None = None,
        enricher: Any | None = None,
    ) -> None:
        self._handlers = handlers
        self._event_filter = event_filter or EventFilter()
        self._enricher = enricher

    async def send_event(self, event: Any) -> None:
        event_type = getattr(event, "event_type", None)
        if event_type and not self._event_filter.is_event_allowed(event_type):
            return
        if self._enricher is not None:
            await self._enricher.enrich_event(event)
        for handler in self._handlers:
            try:
                await handler.send_event(event)
            except Exception:
                logger.exception("handler.send_event failed")

    async def send_metric(self, metric: Any) -> None:
        metric_type = getattr(metric, "metric_type", None)
        if metric_type and not self._event_filter.is_metric_allowed(metric_type):
            return
        if self._enricher is not None:
            await self._enricher.enrich_metric(metric)
        for handler in self._handlers:
            try:
                await handler.send_metric(metric)
            except Exception:
                logger.exception("handler.send_metric failed")

    async def initialize_redis(self, redis_handler: Any) -> None:
        for handler in self._handlers:
            try:
                await handler.initialize_redis(redis_handler)
            except Exception:
                logger.exception("handler.initialize_redis failed")

    async def start(self) -> None:
        for handler in self._handlers:
            try:
                await handler.start()
            except Exception:
                logger.exception("handler.start failed")

    async def stop(self) -> None:
        for handler in self._handlers:
            try:
                await handler.stop()
            except Exception:
                logger.exception("handler.stop failed")

    async def flush_buffer(self) -> None:
        for handler in self._handlers:
            try:
                await handler.flush_buffer()
            except Exception:
                logger.exception("handler.flush_buffer failed")

    async def get_dynamic_rules(self) -> Any | None:
        for handler in self._handlers:
            try:
                result = await handler.get_dynamic_rules()
                if result is not None:
                    return result
            except Exception:
                logger.exception("handler.get_dynamic_rules failed")
        return None

    async def health_check(self) -> bool:
        if not self._handlers:
            return True
        results = []
        for handler in self._handlers:
            try:
                results.append(await handler.health_check())
            except Exception:
                logger.exception("handler.health_check failed")
                results.append(False)
        return all(results)
