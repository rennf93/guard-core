from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import extract_client_ip


class RouteConfigCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "route_config"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        route_config = self.middleware.route_resolver.get_route_config(request)
        request.state.route_config = route_config
        request.state.client_ip = extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        return None
