from typing import Any

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class RateLimitCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "rate_limit"

    async def _send_rate_limit_event(
        self,
        request: GuardRequest,
        event_type: str,
        event_kwargs: dict[str, Any],
    ) -> None:
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            **event_kwargs,
        )

    async def _apply_rate_limit_check(
        self,
        request: GuardRequest,
        client_ip: str,
        rate_limit: int,
        window: int,
        event_type: str,
        event_kwargs: dict[str, Any],
        endpoint_path: str = "",
    ) -> GuardResponse | None:
        result: (
            GuardResponse | None
        ) = await self.middleware.rate_limit_handler.check_rate_limit(
            request,
            client_ip,
            self.middleware.create_error_response,
            endpoint_path=endpoint_path,
            rate_limit=rate_limit,
            rate_limit_window=window,
        )

        if result is not None:
            await self._send_rate_limit_event(request, event_type, event_kwargs)
            if self.config.passive_mode:
                return None

        return result

    async def _check_endpoint_rate_limit(
        self, request: GuardRequest, client_ip: str, endpoint_path: str
    ) -> GuardResponse | None:
        if endpoint_path not in self.config.endpoint_rate_limits:
            return None

        rate_limit, window = self.config.endpoint_rate_limits[endpoint_path]
        return await self._apply_rate_limit_check(
            request,
            client_ip,
            rate_limit,
            window,
            "dynamic_rule_violation",
            {
                "reason": (
                    f"Endpoint-specific rate limit exceeded: {rate_limit} "
                    f"requests per {window}s for {endpoint_path}"
                ),
                "rule_type": "endpoint_rate_limit",
                "endpoint": endpoint_path,
                "rate_limit": rate_limit,
                "window": window,
            },
            endpoint_path=endpoint_path,
        )

    async def _check_route_rate_limit(
        self, request: GuardRequest, client_ip: str, route_config: Any
    ) -> GuardResponse | None:
        if not route_config or route_config.rate_limit is None:
            return None

        window = route_config.rate_limit_window or 60
        return await self._apply_rate_limit_check(
            request,
            client_ip,
            route_config.rate_limit,
            window,
            EVENT_DECORATOR_VIOLATION,
            {
                "reason": (
                    f"Route-specific rate limit exceeded: "
                    f"{route_config.rate_limit} requests per {window}s"
                ),
                "decorator_type": "rate_limiting",
                "violation_type": "rate_limit",
                "rate_limit": route_config.rate_limit,
                "window": window,
            },
            endpoint_path=request.url_path,
        )

    async def _check_geo_rate_limit(
        self, request: GuardRequest, client_ip: str, route_config: Any
    ) -> GuardResponse | None:
        if not route_config or not route_config.geo_rate_limits:
            return None

        geo_handler = self.config.geo_ip_handler
        if not geo_handler:
            return None

        country = geo_handler.get_country(client_ip)
        limits = route_config.geo_rate_limits

        if country and country in limits:
            rate_limit, window = limits[country]
        elif "*" in limits:
            rate_limit, window = limits["*"]
        else:
            return None

        return await self._apply_rate_limit_check(
            request,
            client_ip,
            rate_limit,
            window,
            EVENT_DECORATOR_VIOLATION,
            {
                "reason": (
                    f"Geo rate limit exceeded for {country or 'unknown'}: "
                    f"{rate_limit} requests per {window}s"
                ),
                "decorator_type": "geo_rate_limiting",
                "violation_type": "geo_rate_limit",
                "rate_limit": rate_limit,
                "window": window,
            },
            endpoint_path=request.url_path,
        )

    async def _check_global_rate_limit(
        self, request: GuardRequest, client_ip: str
    ) -> GuardResponse | None:
        result: (
            GuardResponse | None
        ) = await self.middleware.rate_limit_handler.check_rate_limit(
            request, client_ip, self.middleware.create_error_response
        )

        if result is not None and self.config.passive_mode:
            return None

        return result

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        if getattr(request.state, "is_whitelisted", False):
            return None

        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)

        if not client_ip:
            return None

        if route_config and self.middleware.route_resolver.should_bypass_check(
            "rate_limit", route_config
        ):
            return None

        endpoint_path = request.url_path

        if response := await self._check_endpoint_rate_limit(
            request, client_ip, endpoint_path
        ):
            return response

        if response := await self._check_route_rate_limit(
            request, client_ip, route_config
        ):
            return response

        if response := await self._check_geo_rate_limit(
            request, client_ip, route_config
        ):
            return response

        return await self._check_global_rate_limit(request, client_ip)
