from collections.abc import Callable
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Protocol,
    SupportsIndex,
    cast,
    runtime_checkable,
)

from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.sync.handlers.behavior_handler import BehaviorRule

Principal = Any
AuthVerifier = Callable[[SyncGuardRequest, str], Any]


@runtime_checkable
class DecoratedFunction(Protocol):
    _guard_route_id: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


class RouteConfigRevision:
    def __init__(self) -> None:
        self.value = 0

    def bump(self) -> None:
        self.value += 1


class _RevisionTrackedContainer:
    _revision: RouteConfigRevision | None

    def _bump(self) -> None:
        if self._revision is not None:
            self._revision.bump()


class _TrackedList(_RevisionTrackedContainer, list):
    def __init__(
        self,
        iterable: Any = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        list.__init__(self, iterable)
        self._revision = revision

    def append(self, item: Any) -> None:
        self._bump()
        list.append(self, item)

    def extend(self, iterable: Any) -> None:
        self._bump()
        list.extend(self, iterable)

    def insert(self, index: SupportsIndex, item: Any) -> None:
        self._bump()
        list.insert(self, index, item)

    def remove(self, item: Any) -> None:
        self._bump()
        list.remove(self, item)

    def pop(self, index: SupportsIndex = -1) -> Any:
        self._bump()
        return list.pop(self, index)

    def clear(self) -> None:
        self._bump()
        list.clear(self)

    def sort(self, *args: Any, **kwargs: Any) -> None:
        self._bump()
        list.sort(self, *args, **kwargs)

    def reverse(self) -> None:
        self._bump()
        list.reverse(self)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._bump()
        list.__setitem__(self, key, value)

    def __delitem__(self, key: Any) -> None:
        self._bump()
        list.__delitem__(self, key)

    def __add__(self, other: Any) -> Any:
        return list.__add__(self, other)

    def __mul__(self, other: Any) -> Any:
        return list.__mul__(self, other)

    def __iadd__(self, other: Any) -> Any:
        self._bump()
        list.__iadd__(self, other)
        return self

    def __imul__(self, other: Any) -> Any:
        self._bump()
        list.__imul__(self, other)
        return self


class _TrackedDict(_RevisionTrackedContainer, dict):
    def __init__(
        self,
        mapping: Any = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        dict.__init__(self, mapping)
        self._revision = revision

    def __setitem__(self, key: Any, value: Any) -> None:
        self._bump()
        dict.__setitem__(self, key, value)

    def __delitem__(self, key: Any) -> None:
        self._bump()
        dict.__delitem__(self, key)

    def update(self, *args: Any, **kwargs: Any) -> None:
        self._bump()
        dict.update(self, *args, **kwargs)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        self._bump()
        return dict.setdefault(self, key, default)

    def pop(self, *args: Any) -> Any:
        self._bump()
        return dict.pop(self, *args)

    def popitem(self) -> tuple[Any, Any]:
        self._bump()
        return dict.popitem(self)

    def clear(self) -> None:
        self._bump()
        dict.clear(self)

    def __or__(self, other: Any) -> Any:
        return dict.__or__(self, other)

    def __ior__(self, other: Any) -> Any:
        self._bump()
        dict.__ior__(self, other)
        return self


class _TrackedSet(_RevisionTrackedContainer, set):
    def __init__(
        self,
        iterable: Any = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        set.__init__(self, iterable)
        self._revision = revision

    def add(self, item: Any) -> None:
        self._bump()
        set.add(self, item)

    def discard(self, item: Any) -> None:
        self._bump()
        set.discard(self, item)

    def remove(self, item: Any) -> None:
        self._bump()
        set.remove(self, item)

    def pop(self) -> Any:
        self._bump()
        return set.pop(self)

    def clear(self) -> None:
        self._bump()
        set.clear(self)

    def update(self, *others: Any) -> None:
        self._bump()
        set.update(self, *others)

    def intersection_update(self, *others: Any) -> None:
        self._bump()
        set.intersection_update(self, *others)

    def difference_update(self, *others: Any) -> None:
        self._bump()
        set.difference_update(self, *others)

    def symmetric_difference_update(self, other: Any) -> None:
        self._bump()
        set.symmetric_difference_update(self, other)

    def __or__(self, other: Any) -> Any:
        return set.__or__(self, other)

    def __and__(self, other: Any) -> Any:
        return set.__and__(self, other)

    def __sub__(self, other: Any) -> Any:
        return set.__sub__(self, other)

    def __xor__(self, other: Any) -> Any:
        return set.__xor__(self, other)

    def __ior__(self, other: Any) -> Any:
        self._bump()
        set.__ior__(self, other)
        return self

    def __iand__(self, other: Any) -> Any:
        self._bump()
        set.__iand__(self, other)
        return self

    def __isub__(self, other: Any) -> Any:
        self._bump()
        set.__isub__(self, other)
        return self

    def __ixor__(self, other: Any) -> Any:
        self._bump()
        set.__ixor__(self, other)
        return self


_TRACKED_LIST_FIELDS = frozenset(
    {
        "custom_validators",
        "require_referrer",
        "allowed_content_types",
        "blocked_user_agents",
    }
)
_TRACKED_DICT_FIELDS = frozenset(
    {"required_headers", "time_restrictions", "geo_rate_limits"}
)
_TRACKED_SET_FIELDS = frozenset({"block_cloud_providers"})
_REVISION_EXEMPT_ATTRS = frozenset({"_revision", "_initialized"})


class RouteConfig:
    _revision: RouteConfigRevision | None
    _initialized: bool

    def __init__(self, revision: RouteConfigRevision | None = None) -> None:
        object.__setattr__(self, "_revision", revision)
        object.__setattr__(self, "_initialized", False)
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
        self.auth_verifier: AuthVerifier | None = None
        self.api_key_verifier: AuthVerifier | None = None
        self.api_key_header: str | None = None
        self.authorization_header_required: str | None = None
        self.geo_rate_limits: dict[str, tuple[int, int]] | None = None
        self.excluded_detection_headers: set[str] | None = None
        self.excluded_detection_params: set[str] | None = None
        self.excluded_detection_body_fields: set[str] | None = None
        self.enabled_detection_categories: set[str] | None = None
        self.detection_scan_body: bool | None = None
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _TRACKED_LIST_FIELDS and isinstance(value, list):
            value = _TrackedList(value, revision=self._revision)
        elif name in _TRACKED_DICT_FIELDS and isinstance(value, dict):
            value = _TrackedDict(value, revision=self._revision)
        elif name in _TRACKED_SET_FIELDS and isinstance(value, set):
            value = _TrackedSet(value, revision=self._revision)
        object.__setattr__(self, name, value)
        if self._initialized and name not in _REVISION_EXEMPT_ATTRS:
            revision = self._revision
            if revision is not None:
                revision.bump()


class BaseSecurityMixin:
    def _ensure_route_config(self, func: Callable[..., Any]) -> RouteConfig:
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")

    def _apply_route_config(self, func: Callable[..., Any]) -> "DecoratedFunction":
        raise NotImplementedError("This mixin must be used with BaseSecurityDecorator")


class BaseSecurityDecorator:
    def __init__(self, config: SecurityConfig) -> None:
        from guard_core.sync.handlers.behavior_handler import BehaviorTracker

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
