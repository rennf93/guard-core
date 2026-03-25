from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )


class SecurityCheck(ABC):
    def __init__(self, middleware: "SyncGuardMiddlewareProtocol") -> None:
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    @abstractmethod
    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        pass  # pragma: no cover

    @property
    @abstractmethod
    def check_name(self) -> str:
        pass  # pragma: no cover

    def send_event(
        self,
        event_type: str,
        request: SyncGuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        return self.config.passive_mode
