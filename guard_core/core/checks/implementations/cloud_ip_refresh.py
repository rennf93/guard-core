import time
from collections.abc import Collection
from typing import TYPE_CHECKING

from guard_core.core.checks.base import SecurityCheck
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


class CloudIpRefreshCheck(SecurityCheck):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.cloud_handler import cloud_handler

        self.cloud_handler = cloud_handler

    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return bool(config.block_cloud_providers) or config.enable_dynamic_rules

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.block_cloud_providers:
            return None

        if (
            time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            previous_refresh = self.middleware.last_cloud_ip_refresh
            self.middleware.last_cloud_ip_refresh = int(time.time())
            scheduled = await self.cloud_handler.schedule_refresh(
                {str(provider) for provider in self.config.block_cloud_providers},
                ttl=self.config.cloud_ip_refresh_interval,
                refresh=self.middleware.refresh_cloud_ip_ranges,
            )
            if not scheduled:
                self.middleware.last_cloud_ip_refresh = previous_refresh
        return None
