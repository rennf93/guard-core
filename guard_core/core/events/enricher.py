from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any

from guard_core.core.events.event_types import (
    ENRICHMENT_KEY_BEHAVIOR_KEY,
    ENRICHMENT_KEY_DEPLOYMENT_ENV,
    ENRICHMENT_KEY_PROJECT_ID,
    ENRICHMENT_KEY_RECENT_EVENT_COUNT,
    ENRICHMENT_KEY_RULE_ID,
    ENRICHMENT_KEY_RULE_VERSION,
    ENRICHMENT_KEY_SERVICE_NAME,
    ENRICHMENT_KEY_THREAT_SCORE,
)
from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core.enricher")


_THREAT_SCORE_MAP: dict[str, int] = {
    "penetration_attempt": 90,
    "ip_banned": 70,
    "ip_blocked": 50,
    "behavior_violation": 50,
    "cloud_blocked": 50,
    "country_blocked": 50,
    "decorator_violation": 50,
    "authentication_failed": 50,
    "emergency_mode_block": 50,
    "csp_violation": 40,
    "access_denied": 30,
    "user_agent_blocked": 30,
    "rate_limited": 20,
    "redis_error": 40,
    "geo_lookup_failed": 20,
    "pattern_detected": 50,
}
_DEFAULT_THREAT_SCORE = 20

_BEHAVIOR_CORRELATION_WINDOW_SECONDS = 300


class ThreatScorer:
    @staticmethod
    def score_for(event_type: str) -> int:
        return _THREAT_SCORE_MAP.get(event_type, _DEFAULT_THREAT_SCORE)


@dataclass
class EnrichmentContext:
    config: SecurityConfig
    agent_handler: Any | None = None
    dynamic_rule_handler: Any | None = None
    behavior_tracker: Any | None = None


class EventEnricher:
    def __init__(self, context: EnrichmentContext) -> None:
        self._context = context

    async def enrich_event(self, event: Any) -> None:
        try:
            metadata = getattr(event, "metadata", None)
            if metadata is None:
                return
            self._apply_identity(metadata)
            self._apply_threat_score(event, metadata)
            await self._apply_rule_correlation(event, metadata)
            await self._apply_behavior_correlation(event, metadata)
        except Exception:
            logger.exception("event enrichment failed; event will be sent unenriched")

    async def enrich_metric(self, metric: Any) -> None:
        try:
            tags = getattr(metric, "tags", None)
            if tags is None:
                return
            self._apply_identity(tags)
        except Exception:
            logger.exception("metric enrichment failed; metric will be sent unenriched")

    def _apply_identity(self, bag: dict[str, Any]) -> None:
        cfg = self._context.config
        if cfg.agent_project_id:
            bag[ENRICHMENT_KEY_PROJECT_ID] = cfg.agent_project_id
        bag[ENRICHMENT_KEY_SERVICE_NAME] = cfg.otel_service_name
        env = cfg.otel_resource_attributes.get("deployment.environment")
        if env:
            bag[ENRICHMENT_KEY_DEPLOYMENT_ENV] = env

    def _apply_threat_score(self, event: Any, bag: dict[str, Any]) -> None:
        event_type = getattr(event, "event_type", None)
        if not event_type:
            return
        bag[ENRICHMENT_KEY_THREAT_SCORE] = ThreatScorer.score_for(event_type)

    async def _apply_rule_correlation(self, event: Any, bag: dict[str, Any]) -> None:
        rule_handler = self._context.dynamic_rule_handler
        if rule_handler is None or not hasattr(rule_handler, "match_event"):
            return
        match = rule_handler.match_event(event)
        if match is None:
            return
        rule_id, rule_version = match
        bag[ENRICHMENT_KEY_RULE_ID] = rule_id
        bag[ENRICHMENT_KEY_RULE_VERSION] = rule_version

    async def _apply_behavior_correlation(
        self, event: Any, bag: dict[str, Any]
    ) -> None:
        tracker = self._context.behavior_tracker
        ip = getattr(event, "ip_address", None)
        if tracker is None or not ip:
            return
        if not hasattr(tracker, "get_recent_event_count"):
            return
        window_seconds = _BEHAVIOR_CORRELATION_WINDOW_SECONDS
        count = tracker.get_recent_event_count(ip, window_seconds)
        bag[ENRICHMENT_KEY_RECENT_EVENT_COUNT] = count
        bucket = int(time.time() // window_seconds)
        service = self._context.config.otel_service_name
        raw = f"{ip}|{service}|{bucket}".encode()
        bag[ENRICHMENT_KEY_BEHAVIOR_KEY] = hashlib.sha256(raw).hexdigest()[:16]
