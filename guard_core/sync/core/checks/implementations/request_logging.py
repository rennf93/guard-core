from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import log_activity


class RequestLoggingCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "request_logging"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        log_activity(request, self.logger, level=self.config.log_request_level)
        return None
