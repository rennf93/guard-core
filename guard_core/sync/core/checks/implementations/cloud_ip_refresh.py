import time

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class CloudIpRefreshCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        if (
            self.config.block_cloud_providers
            and time.time() - self.middleware.last_cloud_ip_refresh
            > self.config.cloud_ip_refresh_interval
        ):
            self.middleware.refresh_cloud_ip_ranges()
        return None
