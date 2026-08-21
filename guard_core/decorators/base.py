from collections.abc import Callable
from datetime import datetime, timezone
from typing import (
    Any,
    Protocol,
    cast,
    runtime_checkable,
)

from guard_core.decorators.route_config import (
    _REVISION_EXEMPT_ATTRS,
    _TRACKED_DICT_FIELDS,
    _TRACKED_LIST_FIELDS,
    _TRACKED_SET_FIELDS,
    AuthVerifier,
    Principal,
    RouteConfig,
    RouteConfigRevision,
    _RevisionTrackedContainer,
    _TrackedDict,
    _TrackedList,
    _TrackedSet,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest

__all__ = [
    "AuthVerifier",
    "BaseSecurityDecorator",
    "BaseSecurityMixin",
    "DecoratedFunction",
    "Principal",
    "RouteConfig",
    "RouteConfigRevision",
    "get_route_decorator_config",
    "_REVISION_EXEMPT_ATTRS",
    "_RevisionTrackedContainer",
    "_TRACKED_DICT_FIELDS",
    "_TRACKED_LIST_FIELDS",
    "_TRACKED_SET_FIELDS",
    "_TrackedDict",
    "_TrackedList",
    "_TrackedSet",
]


@runtime_checkable
class DecoratedFunction(Protocol):
    _guard_route_id: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


class BaseSecurityMixin:
    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")

    def _apply_route_config(self, func: Callable[..., Any]) -> "DecoratedFunction":
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")


class BaseSecurityDecorator:
    def __init__(self, config: SecurityConfig) -> None:
        from guard_core.handlers.behavior_handler import BehaviorTracker

        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        self._route_config_revision = RouteConfigRevision()
        self.behavior_tracker = BehaviorTracker(config)
        self.agent_handler: Any = None

    @property
    def route_config_revision(self) -> int:
        return self._route_config_revision.value

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: Callable[..., Any]) -> str:
        return f"{func.__module__}.{func.__qualname__}"

    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            config = RouteConfig(self._route_config_revision)
            config.enable_suspicious_detection = (
                self.config.enable_penetration_detection
            )
            self._route_configs[route_id] = config
            self._route_config_revision.bump()
        return self._route_configs[route_id]

    def _apply_route_config(self, func: Callable[..., Any]) -> DecoratedFunction:
        route_id = self._get_route_id(func)
        cast(Any, func)._guard_route_id = route_id
        return cast(DecoratedFunction, func)

    async def initialize_behavior_tracking(self, redis_handler: Any = None) -> None:
        if redis_handler:
            await self.behavior_tracker.initialize_redis(redis_handler)

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler
        await self.behavior_tracker.initialize_agent(agent_handler)

    async def send_decorator_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        decorator_type: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_core.utils import (
                extract_client_ip,
                get_pipeline_response_time,
            )

            client_ip = await extract_client_ip(
                request, self.config, self.agent_handler
            )

            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

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

            await self.agent_handler.send_event(event)

        except Exception as e:
            import logging

            logging.getLogger("guard_core.decorators.base").error(
                f"Failed to send decorator event to agent: {e}"
            )

    async def send_access_denied_event(
        self,
        request: GuardRequest,
        reason: str,
        decorator_type: str,
        **metadata: Any,
    ) -> None:
        await self.send_decorator_event(
            event_type="access_denied",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=decorator_type,
            **metadata,
        )

    async def send_authentication_failed_event(
        self,
        request: GuardRequest,
        reason: str,
        auth_type: str,
        **metadata: Any,
    ) -> None:
        await self.send_decorator_event(
            event_type="authentication_failed",
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type="authentication",
            auth_type=auth_type,
            **metadata,
        )

    async def send_rate_limit_event(
        self,
        request: GuardRequest,
        limit: int,
        window: int,
        **metadata: Any,
    ) -> None:
        await self.send_decorator_event(
            event_type="rate_limited",
            request=request,
            action_taken="blocked",
            reason=f"Rate limit exceeded: {limit} requests per {window}s",
            decorator_type="rate_limiting",
            limit=limit,
            window=window,
            **metadata,
        )

    async def send_decorator_violation_event(
        self,
        request: GuardRequest,
        violation_type: str,
        reason: str,
        **metadata: Any,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_DECORATOR_VIOLATION

        await self.send_decorator_event(
            event_type=EVENT_DECORATOR_VIOLATION,
            request=request,
            action_taken="blocked",
            reason=reason,
            decorator_type=violation_type,
            **metadata,
        )


def get_route_decorator_config(
    request: GuardRequest, decorator_handler: BaseSecurityDecorator
) -> RouteConfig | None:
    route_id = getattr(request.state, "guard_route_id", None)
    if route_id:
        return decorator_handler.get_route_config(route_id)
    return None
