from collections.abc import Callable
from typing import Any

from guard_core.sync.decorators.base import BaseSecurityMixin, DecoratedFunction


class AuthenticationMixin(BaseSecurityMixin):
    def require_https(self) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.require_https = True
            return self._apply_route_config(func)

        return decorator

    def require_auth(
        self, type: str = "bearer"
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.auth_required = type
            return self._apply_route_config(func)

        return decorator

    def api_key_auth(
        self, header_name: str = "X-API-Key"
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.api_key_required = True
            route_config.required_headers[header_name] = "required"
            return self._apply_route_config(func)

        return decorator

    def require_headers(
        self, headers: dict[str, str]
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.required_headers.update(headers)
            return self._apply_route_config(func)

        return decorator
