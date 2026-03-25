from collections.abc import Callable

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class BypassHandler:
    def __init__(self, context: BypassContext) -> None:
        self.context = context

    def handle_passthrough(
        self,
        request: SyncGuardRequest,
        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,
    ) -> GuardResponse | None:
        if not request.client_host:
            if call_next:
                response = call_next(request)
                return self.context.response_factory.apply_modifier(response)
            return None

        if self.context.validator.is_path_excluded(request):
            if call_next:
                response = call_next(request)
                return self.context.response_factory.apply_modifier(response)
            return None

        return None

    def handle_security_bypass(
        self,
        request: SyncGuardRequest,
        call_next: Callable[[SyncGuardRequest], GuardResponse] | None = None,
        route_config: RouteConfig | None = None,
    ) -> GuardResponse | None:
        if not route_config or not self.context.route_resolver.should_bypass_check(
            "all", route_config
        ):
            return None

        self.context.event_bus.send_middleware_event(
            event_type="security_bypass",
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=str(request.url_path),
        )

        if not self.context.config.passive_mode:
            if call_next:
                response = call_next(request)
                return self.context.response_factory.apply_modifier(response)
            return None

        return None
