from dataclasses import dataclass, field
from logging import Logger
from typing import TYPE_CHECKING, Any

from guard_core.models import SecurityConfig
from guard_core.sync.core.events import MetricsCollector
from guard_core.sync.decorators.base import BaseSecurityDecorator

if TYPE_CHECKING:
    from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline


@dataclass
class ResponseContext:
    config: SecurityConfig
    logger: Logger
    metrics_collector: MetricsCollector

    agent_handler: Any | None = None
    guard_decorator: BaseSecurityDecorator | None = None
    response_factory: Any = field(default=None)
    security_pipeline: "SecurityCheckPipeline | None" = None
