from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class RouteConfigResolver:
    def __init__(self, context: RoutingContext):
        self.context = context

    def get_route_config(self, request: SyncGuardRequest) -> RouteConfig | None:
        guard_decorator = self.context.guard_decorator
        if not guard_decorator:
            guard_decorator = getattr(request.state, "guard_decorator", None)
        if not guard_decorator:
            return None

        route_id = getattr(request.state, "guard_route_id", None)
        if not route_id:
            return None

        return guard_decorator.get_route_config(route_id)

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        if route_config and route_config.block_cloud_providers:
            return list(route_config.block_cloud_providers)
        if self.context.config.block_cloud_providers:
            return list(self.context.config.block_cloud_providers)
        return None
