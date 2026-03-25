from dataclasses import dataclass
from logging import Logger

from guard_core.models import SecurityConfig
from guard_core.sync.core.events import SecurityEventBus
from guard_core.sync.decorators.base import BaseSecurityDecorator


@dataclass
class BehavioralContext:
    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
