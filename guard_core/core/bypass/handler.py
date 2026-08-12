from collections.abc import Awaitable, Callable

from guard_core.core.bypass.context import BypassContext
from guard_core.decorators.base import RouteConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class BypassHandler:
    def __init__(self, context: BypassContext) -> None:
        self.context = context

    async def handle_passthrough(
        self,
        request: GuardRequest,
        call_next: Callable[[GuardRequest], Awaitable[GuardResponse]],
    ) -> GuardResponse | None:
        if not request.client_host:
            response = await call_next(request)
            return await self.context.response_factory.apply_modifier(response)

        if await self.context.validator.is_path_excluded(request):
            request.state.guard_exclusion_scoped = True

        return None

    async def handle_security_bypass(
        self,
        request: GuardRequest,
        call_next: Callable[[GuardRequest], Awaitable[GuardResponse]],
        route_config: RouteConfig | None,
    ) -> GuardResponse | None:
        if not route_config or not self.context.route_resolver.should_bypass_check(
            "all", route_config
        ):
            return None

        await self.context.event_bus.send_middleware_event(
            event_type="security_bypass",
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=str(request.url_path),
        )

        if not self.context.config.passive_mode:
            response = await call_next(request)
            return await self.context.response_factory.apply_modifier(response)

        return None
