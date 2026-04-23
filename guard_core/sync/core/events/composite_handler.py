from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("guard_core")


class CompositeAgentHandler:
    def __init__(self, handlers: list[Any]) -> None:
        self._handlers = handlers

    def send_event(self, event: Any) -> None:
        for handler in self._handlers:
            try:
                handler.send_event(event)
            except Exception:
                logger.exception("handler.send_event failed")

    def send_metric(self, metric: Any) -> None:
        for handler in self._handlers:
            try:
                handler.send_metric(metric)
            except Exception:
                logger.exception("handler.send_metric failed")

    def initialize_redis(self, redis_handler: Any) -> None:
        for handler in self._handlers:
            try:
                handler.initialize_redis(redis_handler)
            except Exception:
                logger.exception("handler.initialize_redis failed")

    def start(self) -> None:
        for handler in self._handlers:
            try:
                handler.start()
            except Exception:
                logger.exception("handler.start failed")

    def stop(self) -> None:
        for handler in self._handlers:
            try:
                handler.stop()
            except Exception:
                logger.exception("handler.stop failed")

    def flush_buffer(self) -> None:
        for handler in self._handlers:
            try:
                handler.flush_buffer()
            except Exception:
                logger.exception("handler.flush_buffer failed")

    def get_dynamic_rules(self) -> Any | None:
        for handler in self._handlers:
            try:
                result = handler.get_dynamic_rules()
                if result is not None:
                    return result
            except Exception:
                logger.exception("handler.get_dynamic_rules failed")
        return None

    def health_check(self) -> bool:
        if not self._handlers:
            return True
        results = []
        for handler in self._handlers:
            try:
                results.append(handler.health_check())
            except Exception:
                logger.exception("handler.health_check failed")
                results.append(False)
        return all(results)
