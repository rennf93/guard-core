from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core.enricher")


@dataclass
class EnrichmentContext:
    config: SecurityConfig
    agent_handler: Any | None = None
    dynamic_rule_handler: Any | None = None
    behavior_tracker: Any | None = None


class EventEnricher:
    def __init__(self, context: EnrichmentContext) -> None:
        self._context = context

    def enrich_event(self, event: Any) -> None:
        try:
            metadata = getattr(event, "metadata", None)
            if metadata is None:
                return
            self._apply_identity(metadata)
            self._apply_threat_score(event, metadata)
            self._apply_rule_correlation(event, metadata)
            self._apply_behavior_correlation(event, metadata)
        except Exception:
            logger.exception("event enrichment failed; event will be sent unenriched")

    def enrich_metric(self, metric: Any) -> None:
        try:
            tags = getattr(metric, "tags", None)
            if tags is None:
                return
            self._apply_identity(tags)
        except Exception:
            logger.exception("metric enrichment failed; metric will be sent unenriched")

    def _apply_identity(self, bag: dict[str, Any]) -> None:
        return None

    def _apply_threat_score(self, event: Any, bag: dict[str, Any]) -> None:
        return None

    def _apply_rule_correlation(self, event: Any, bag: dict[str, Any]) -> None:
        return None

    def _apply_behavior_correlation(self, event: Any, bag: dict[str, Any]) -> None:
        return None
