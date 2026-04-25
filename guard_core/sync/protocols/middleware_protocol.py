from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


@runtime_checkable
class SyncGuardMiddlewareProtocol(Protocol):
    config: SecurityConfig
    logger: logging.Logger
    last_cloud_ip_refresh: int
    suspicious_request_counts: dict[str, dict[str, int]]

    @property
    def event_bus(self) -> Any: ...
    @property
    def route_resolver(self) -> Any: ...
    @property
    def response_factory(self) -> Any: ...
    @property
    def rate_limit_handler(self) -> Any: ...
    @property
    def agent_handler(self) -> Any: ...
    @property
    def geo_ip_handler(self) -> Any: ...
    @property
    def guard_response_factory(self) -> Any: ...

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse: ...

    def refresh_cloud_ip_ranges(self) -> None: ...
