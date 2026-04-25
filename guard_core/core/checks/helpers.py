import re
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

from guard_core.decorators.base import RouteConfig
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import detect_penetration_attempt


def is_ip_in_blacklist(client_ip: str, ip_addr: object, blacklist: list[str]) -> bool:
    for blocked in blacklist:
        if "/" in blocked:
            if ip_addr in ip_network(blocked, strict=False):
                return True
        elif client_ip == blocked:
            return True
    return False


def is_ip_in_whitelist(
    client_ip: str, ip_addr: object, whitelist: list[str]
) -> bool | None:
    if not whitelist:
        return None

    for allowed in whitelist:
        if "/" in allowed:
            if ip_addr in ip_network(allowed, strict=False):
                return True
        elif client_ip == allowed:
            return True
    return False


def check_country_access(
    client_ip: str, route_config: RouteConfig, geo_ip_handler: Any
) -> bool | None:
    if not geo_ip_handler:
        return None

    country = None

    if route_config.blocked_countries:
        country = geo_ip_handler.get_country(client_ip)
        if country and country in route_config.blocked_countries:
            return False

    if route_config.whitelist_countries:
        if country is None:
            country = geo_ip_handler.get_country(client_ip)

        if country:
            return country in route_config.whitelist_countries
        return False

    return None


def _check_ip_blacklist(
    client_ip: str, ip_addr: object, route_config: RouteConfig
) -> bool:
    if not route_config.ip_blacklist:
        return False
    return is_ip_in_blacklist(client_ip, ip_addr, route_config.ip_blacklist)


def _check_ip_whitelist(
    client_ip: str, ip_addr: object, route_config: RouteConfig
) -> bool | None:
    return is_ip_in_whitelist(client_ip, ip_addr, route_config.ip_whitelist or [])


async def check_route_ip_access(
    client_ip: str, route_config: RouteConfig, middleware: Any
) -> bool | None:
    try:
        ip_addr = ip_address(client_ip)

        if _check_ip_blacklist(client_ip, ip_addr, route_config):
            return False

        whitelist_result = _check_ip_whitelist(client_ip, ip_addr, route_config)
        if whitelist_result is not None:
            return whitelist_result

        country_result = check_country_access(
            client_ip, route_config, middleware.geo_ip_handler
        )
        if country_result is not None:
            return country_result

        return None
    except ValueError:
        return False


async def check_user_agent_allowed(
    user_agent: str, route_config: RouteConfig | None, config: Any
) -> bool:
    from guard_core.utils import is_user_agent_allowed as global_user_agent_check

    if route_config and route_config.blocked_user_agents:
        for pattern in route_config.blocked_user_agents:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return False

    return await global_user_agent_check(user_agent, config)


def validate_auth_header(auth_header: str, auth_type: str) -> tuple[bool, str]:
    if auth_type == "bearer":
        if not auth_header.startswith("Bearer "):
            return False, "Missing or invalid Bearer token"
    elif auth_type == "basic":
        if not auth_header.startswith("Basic "):
            return False, "Missing or invalid Basic authentication"
    else:
        if not auth_header:
            return False, f"Missing {auth_type} authentication"

    return True, ""


def is_referrer_domain_allowed(referrer: str, allowed_domains: list[str]) -> bool:
    try:
        referrer_domain = urlparse(referrer).netloc.lower()
        for allowed_domain in allowed_domains:
            if referrer_domain == allowed_domain.lower() or referrer_domain.endswith(
                f".{allowed_domain.lower()}"
            ):
                return True
        return False
    except Exception:
        return False


def _get_effective_penetration_setting(
    config: SecurityConfig, route_config: RouteConfig | None
) -> tuple[bool, bool | None]:
    route_specific_detection = None
    penetration_enabled = config.enable_penetration_detection

    if route_config and hasattr(route_config, "enable_suspicious_detection"):
        route_specific_detection = route_config.enable_suspicious_detection
        penetration_enabled = route_specific_detection

    return penetration_enabled, route_specific_detection


def _get_detection_disabled_reason(
    config: SecurityConfig, route_specific_detection: bool | None
) -> str:
    if route_specific_detection is False and config.enable_penetration_detection:
        return "disabled_by_decorator"
    return "not_enabled"


async def detect_penetration_patterns(
    request: GuardRequest,
    route_config: RouteConfig | None,
    config: SecurityConfig,
    should_bypass_check_fn: Any,
) -> DetectionResult:
    penetration_enabled, route_specific_detection = _get_effective_penetration_setting(
        config, route_config
    )

    if penetration_enabled and not should_bypass_check_fn("penetration", route_config):
        return await detect_penetration_attempt(request, config, route_config)

    reason = _get_detection_disabled_reason(config, route_specific_detection)
    return DetectionResult(is_threat=False, trigger_info=reason)
