from dataclasses import dataclass
from logging import Logger

from guard_core.models import SecurityConfig
from guard_core.sync.core.events import SecurityEventBus


@dataclass
class ValidationContext:
    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
