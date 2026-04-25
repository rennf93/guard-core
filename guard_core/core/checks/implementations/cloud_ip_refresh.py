import time

from guard_core.core.checks.base import SecurityCheck
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class CloudIpRefreshCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if not self.config.block_cloud_providers:
            return None

        providers = self.config.block_cloud_providers
        has_any_ranges = any(
            cloud_handler.ip_ranges.get(provider) for provider in providers
        )

        if self.config.lazy_init and not has_any_ranges:
            await cloud_handler.refresh_async(
                providers, ttl=self.config.cloud_ip_refresh_interval
            )
            self.middleware.last_cloud_ip_refresh = int(time.time())
            return None

        if (
            time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            await self.middleware.refresh_cloud_ip_ranges()
        return None
