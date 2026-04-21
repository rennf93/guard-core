from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


class SecurityCheck(ABC):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    @abstractmethod
    async def check(self, request: GuardRequest) -> GuardResponse | None: ...

    @property
    @abstractmethod
    def check_name(self) -> str: ...

    async def post_response(
        self, request: GuardRequest, response: GuardResponse
    ) -> GuardResponse | None:
        return None

    async def send_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return await self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        return self.config.passive_mode
