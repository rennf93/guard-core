from collections.abc import Callable
from typing import Any

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.decorators.base import BaseSecurityMixin
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class ContentFilteringMixin(BaseSecurityMixin):
    def block_user_agents(
        self, patterns: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.blocked_user_agents.extend(patterns)
            return self._apply_route_config(func)

        return decorator

    def content_type_filter(
        self, allowed_types: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.allowed_content_types = allowed_types
            return self._apply_route_config(func)

        return decorator

    def max_request_size(
        self, size_bytes: int
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.max_request_size = size_bytes
            return self._apply_route_config(func)

        return decorator

    def require_referrer(
        self, allowed_domains: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.require_referrer = allowed_domains
            return self._apply_route_config(func)

        return decorator

    def custom_validation(
        self,
        validator: Callable[[SyncGuardRequest], GuardResponse | None],
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(validator)
            return self._apply_route_config(func)

        return decorator
