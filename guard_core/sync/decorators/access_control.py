from collections.abc import Callable
from typing import Any

from guard_core.sync.decorators.base import BaseSecurityMixin, DecoratedFunction


class AccessControlMixin(BaseSecurityMixin):
    def require_ip(
        self,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            if whitelist:
                route_config.ip_whitelist = whitelist
            if blacklist:
                route_config.ip_blacklist = blacklist
            return self._apply_route_config(func)

        return decorator

    def block_countries(
        self, countries: list[str]
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.blocked_countries = countries
            return self._apply_route_config(func)

        return decorator

    def allow_countries(
        self, countries: list[str]
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.whitelist_countries = countries
            return self._apply_route_config(func)

        return decorator

    def block_clouds(
        self, providers: list[str] | None = None
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            if providers is None:
                route_config.block_cloud_providers = {"AWS", "GCP", "Azure"}
            else:
                route_config.block_cloud_providers = set(providers)
            return self._apply_route_config(func)

        return decorator

    def bypass(
        self, checks: list[str]
    ) -> Callable[[Callable[..., Any]], DecoratedFunction]:
        def decorator(func: Callable[..., Any]) -> DecoratedFunction:
            route_config = self._ensure_route_config(func)
            route_config.bypassed_checks.update(checks)
            return self._apply_route_config(func)

        return decorator
