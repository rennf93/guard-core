from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class RouteConfig:
    def __init__(self) -> None:
        self.rate_limit: int | None = None
        self.rate_limit_window: int | None = None
        self.ip_whitelist: list[str] | None = None
        self.ip_blacklist: list[str] | None = None
        self.blocked_countries: list[str] | None = None
        self.whitelist_countries: list[str] | None = None
        self.bypassed_checks: set[str] = set()
        self.require_https: bool = False
        self.auth_required: str | None = None
        self.custom_validators: list[Callable] = []
        self.blocked_user_agents: list[str] = []
        self.required_headers: dict[str, str] = {}
        self.behavior_rules: list[BehaviorRule] = []
        self.block_cloud_providers: set[str] = set()
        self.max_request_size: int | None = None
        self.allowed_content_types: list[str] | None = None
        self.time_restrictions: dict[str, str] | None = None
        self.enable_suspicious_detection: bool = True
        self.require_referrer: list[str] | None = None
        self.api_key_required: bool = False
        self.session_limits: dict[str, int] | None = None
        self.geo_rate_limits: dict[str, tuple[int, int]] | None = None
        self.excluded_detection_headers: set[str] | None = None
        self.excluded_detection_params: set[str] | None = None
        self.excluded_detection_body_fields: set[str] | None = None
        self.enabled_detection_categories: set[str] | None = None


class BaseSecurityMixin:
    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")

    def _apply_route_config(self, func: Callable[..., Any]) -> Callable[..., Any]:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")


class BaseSecurityDecorator:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        self.behavior_tracker = BehaviorTracker(config)
        self.agent_handler: Any = None

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: Callable[..., Any]) -> str:
        return f"{func.__module__}.{func.__qualname__}"

    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            config = RouteConfig()
            config.enable_suspicious_detection = (
                self.config.enable_penetration_detection
            )
            self._route_configs[route_id] = config
        return self._route_configs[route_id]

    def _apply_route_config(self, func: Callable[..., Any]) -> Callable[..., Any]:
        route_id = self._get_route_id(func)
        func._guard_route_id = route_id  # type: ignore[attr-defined]
        return func

    def initialize_behavior_tracking(self, redis_handler: Any = None) -> None:
        if redis_handler:
            self.behavior_tracker.initialize_redis(redis_handler)

    def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler
        self.behavior_tracker.initialize_agent(agent_handler)

    def send_decorator_event(
        self,
        event_type: str,
        request: SyncGuardRequest,
        action_taken: str,
        reason: str,
        decorator_type: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_core.sync.utils import (
                extract_client_ip,
                get_pipeline_response_time,
            )

            client_ip = extract_client_ip(request, self.config, self.agent_handler)

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=client_ip,
                country=None,
                user_agent=request.headers.get("User-Agent"),
                action_taken=action_taken,
                reason=reason,
                endpoint=str(request.url_path),
                method=request.method,
                response_time=get_pipeline_response_time(request),
                decorator_type=decorator_type,
                metadata=kwargs,
            )

            self.agent_handler.send_event(event)

        except Exception as e:
            import logging

            logging.getLogger("guard_core.decorators.base").error(
                f"Failed to send decorator event to agent: {e}"
            )

    def send_access_denied_event(
        self,
        request: SyncGuardRequest,
        reason: str,
        decorator_type: str,
        **metadata: Any,
    ) -> None:
        self.send_decorator_event(
            event_type="access_denied",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=decorator_type,
            **metadata,
        )

    def send_authentication_failed_event(
        self,
        request: SyncGuardRequest,
        reason: str,
        auth_type: str,
        **metadata: Any,
    ) -> None:
        self.send_decorator_event(
            event_type="authentication_failed",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type="authentication",
            auth_type=auth_type,
            **metadata,
        )

    def send_rate_limit_event(
        self,
        request: SyncGuardRequest,
        limit: int,
        window: int,
        **metadata: Any,
    ) -> None:
        self.send_decorator_event(
            event_type="rate_limited",
            request=request,
            action_taken="blocked",
            reason=f"Rate limit exceeded: {limit} requests per {window}s",
            decorator_type="rate_limiting",
            limit=limit,
            window=window,
            **metadata,
        )

    def send_decorator_violation_event(
        self,
        request: SyncGuardRequest,
        violation_type: str,
        reason: str,
        **metadata: Any,
    ) -> None:
        from guard_core.sync.core.events.event_types import EVENT_DECORATOR_VIOLATION

        self.send_decorator_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=violation_type,
            **metadata,
        )


def get_route_decorator_config(
    request: SyncGuardRequest, decorator_handler: BaseSecurityDecorator
) -> RouteConfig | None:
    route_id = getattr(request.state, "guard_route_id", None)
    if route_id:
        return decorator_handler.get_route_config(route_id)
    return None
