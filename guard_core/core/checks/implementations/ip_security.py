from typing import TYPE_CHECKING, Any

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import check_country_access, check_route_ip_access
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_IP_BLOCKED,
)
from guard_core.decorators.base import RouteConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import check_ip_access, log_activity

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol


def _route_overrides_ip_lists(route_config: RouteConfig | None) -> bool:
    return bool(route_config and route_config.ip_whitelist)


def _route_country_whitelist_matched(
    client_ip: str, route_config: RouteConfig | None, geo_ip_handler: Any
) -> bool:
    if not route_config:
        return False
    return check_country_access(client_ip, route_config, geo_ip_handler) is True


def _resolve_is_whitelisted(
    client_ip: str,
    route_config: RouteConfig | None,
    config: Any,
    is_allowed: bool,
    skip_ip_lists: bool,
) -> bool:
    return is_allowed and bool(config.whitelist) and not skip_ip_lists


class IpSecurityCheck(SecurityCheck):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        super().__init__(middleware)
        from guard_core.handlers.ipban_handler import ip_ban_manager

        self.ip_ban_manager = ip_ban_manager

    @property
    def check_name(self) -> str:
        return "ip_security"

    async def _check_banned_ip(
        self, request: GuardRequest, client_ip: str, route_config: RouteConfig | None
    ) -> GuardResponse | None:
        if self.middleware.route_resolver.should_bypass_check("ip_ban", route_config):
            return None

        if not await self.ip_ban_manager.is_ip_banned(client_ip):
            return None

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Banned IP attempted access: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Banned IP attempted access: {client_ip}",
            ip_address=client_ip,
            filter_type="banned",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="IP address banned",
            )

        return None

    async def _check_route_ip_restrictions(
        self, request: GuardRequest, client_ip: str, route_config: RouteConfig
    ) -> GuardResponse | None:
        route_allowed = await check_route_ip_access(
            client_ip, route_config, self.middleware
        )

        if route_allowed is None or route_allowed:
            return None

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed by route config: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"IP {client_ip} blocked",
            decorator_type="access_control",
            violation_type="ip_restriction",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="Forbidden",
            )

        return None

    async def _check_global_ip_restrictions(
        self,
        request: GuardRequest,
        client_ip: str,
        route_config: RouteConfig | None = None,
    ) -> GuardResponse | None:
        skip_ip_lists = _route_overrides_ip_lists(route_config)
        skip_countries = _route_country_whitelist_matched(
            client_ip, route_config, self.middleware.geo_ip_handler
        )

        access_result = await check_ip_access(
            client_ip,
            self.config,
            self.middleware.geo_ip_handler,
            skip_ip_lists=skip_ip_lists,
            skip_countries=skip_countries,
        )

        request.state.is_whitelisted = _resolve_is_whitelisted(
            client_ip, route_config, self.config, access_result.allowed, skip_ip_lists
        )

        if access_result.allowed:
            return None

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed: {client_ip} - {access_result.reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        event_kwargs: dict[str, Any] = {}
        if access_result.cloud_provider:
            event_kwargs["cloud_provider"] = access_result.cloud_provider
        if access_result.network:
            event_kwargs["network"] = access_result.network

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=access_result.reason,
            ip_address=client_ip,
            filter_type="global",
            **event_kwargs,
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="Forbidden",
            )

        return None

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        ban_response = await self._check_banned_ip(request, client_ip, route_config)
        if ban_response:
            return ban_response

        if self.middleware.route_resolver.should_bypass_check("ip", route_config):
            return None

        if route_config:
            route_response = await self._check_route_ip_restrictions(
                request, client_ip, route_config
            )
            if route_response:
                return route_response

        return await self._check_global_ip_restrictions(
            request, client_ip, route_config
        )
