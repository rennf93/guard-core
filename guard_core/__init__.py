import logging
from importlib import import_module
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from guard_core.decorators import RouteConfig, SecurityDecorator
    from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
    from guard_core.handlers.cloud_handler import CloudManager, cloud_handler
    from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager
    from guard_core.handlers.ipinfo_handler import IPInfoManager
    from guard_core.handlers.ratelimit_handler import (
        RateLimitManager,
        rate_limit_handler,
    )
    from guard_core.handlers.redis_handler import RedisManager, redis_handler
    from guard_core.handlers.security_headers_handler import (
        SecurityHeadersManager,
        security_headers_manager,
    )
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler
    from guard_core.models import SecurityConfig
    from guard_core.protocols.geo_ip_protocol import GeoIPHandler
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol
    from guard_core.protocols.request_protocol import GuardRequest
    from guard_core.protocols.response_protocol import (
        GuardResponse,
        GuardResponseFactory,
    )

__all__ = [
    "SecurityConfig",
    "SecurityDecorator",
    "RouteConfig",
    "BehaviorTracker",
    "BehaviorRule",
    "ip_ban_manager",
    "IPBanManager",
    "cloud_handler",
    "CloudManager",
    "IPInfoManager",
    "rate_limit_handler",
    "RateLimitManager",
    "redis_handler",
    "RedisManager",
    "security_headers_manager",
    "SecurityHeadersManager",
    "sus_patterns_handler",
    "GeoIPHandler",
    "RedisHandlerProtocol",
    "GuardRequest",
    "GuardResponse",
    "GuardResponseFactory",
]

_MODULE_BY_NAME: dict[str, str] = {
    "SecurityConfig": "guard_core.models",
    "SecurityDecorator": "guard_core.decorators",
    "RouteConfig": "guard_core.decorators",
    "BehaviorTracker": "guard_core.handlers.behavior_handler",
    "BehaviorRule": "guard_core.handlers.behavior_handler",
    "ip_ban_manager": "guard_core.handlers.ipban_handler",
    "IPBanManager": "guard_core.handlers.ipban_handler",
    "cloud_handler": "guard_core.handlers.cloud_handler",
    "CloudManager": "guard_core.handlers.cloud_handler",
    "IPInfoManager": "guard_core.handlers.ipinfo_handler",
    "rate_limit_handler": "guard_core.handlers.ratelimit_handler",
    "RateLimitManager": "guard_core.handlers.ratelimit_handler",
    "redis_handler": "guard_core.handlers.redis_handler",
    "RedisManager": "guard_core.handlers.redis_handler",
    "security_headers_manager": "guard_core.handlers.security_headers_handler",
    "SecurityHeadersManager": "guard_core.handlers.security_headers_handler",
    "sus_patterns_handler": "guard_core.handlers.suspatterns_handler",
    "GeoIPHandler": "guard_core.protocols.geo_ip_protocol",
    "RedisHandlerProtocol": "guard_core.protocols.redis_protocol",
    "GuardRequest": "guard_core.protocols.request_protocol",
    "GuardResponse": "guard_core.protocols.response_protocol",
    "GuardResponseFactory": "guard_core.protocols.response_protocol",
}


def __getattr__(name: str) -> Any:
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


def _mute_pydantic_plugin_instrumentation() -> None:
    """Opt guard-agent's hot-path telemetry models out of pydantic plugin
    instrumentation (e.g. logfire.instrument_pydantic()).

    SecurityEvent/SecurityMetric are validated per request and EventBatch
    re-validates every buffered event on each flush, so an instrumented host
    app would otherwise emit a span per security event — hundreds of
    thousands a day under real traffic. plugin_settings is only read while
    building a model's validator, hence the forced rebuild.
    """
    try:
        from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric
    except ImportError:
        return
    try:
        for model in (SecurityEvent, SecurityMetric, EventBatch):
            plugin_settings = cast(
                "dict[str, Any]",
                model.model_config.setdefault("plugin_settings", {}),
            )
            plugin_settings["logfire"] = {"record": "off"}
            model.model_rebuild(force=True)
    except Exception:
        logging.getLogger("guard_core").warning(
            "Could not opt guard-agent telemetry models out of pydantic "
            "plugin instrumentation",
            exc_info=True,
        )


_mute_pydantic_plugin_instrumentation()
