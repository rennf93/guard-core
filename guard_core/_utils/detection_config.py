from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.models import SecurityConfig


def _resolve_excluded_params(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str]:
    if route_config is not None and route_config.excluded_detection_params is not None:
        return {k.lower() for k in route_config.excluded_detection_params}
    if config is not None:
        return {k.lower() for k in config.excluded_detection_params}
    return set()


def _resolve_excluded_body_fields(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str]:
    if (
        route_config is not None
        and route_config.excluded_detection_body_fields is not None
    ):
        return {k.lower() for k in route_config.excluded_detection_body_fields}
    if config is not None:
        return {k.lower() for k in config.excluded_detection_body_fields}
    return set()


def _resolve_enabled_categories(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str] | None:
    if (
        route_config is not None
        and route_config.enabled_detection_categories is not None
    ):
        return set(route_config.enabled_detection_categories)
    if config is not None:
        return set(config.enabled_detection_categories)
    return None


def _resolve_scan_body(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> bool:
    if route_config is not None and route_config.detection_scan_body is not None:
        return route_config.detection_scan_body
    if config is not None:
        return config.detection_scan_body
    return True


_DEFAULT_EXCLUDED_HEADERS: frozenset[str] = frozenset(
    {
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "connection",
        "origin",
        "referer",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    }
)


def _resolve_excluded_headers(
    config: "SecurityConfig | None", route_config: "RouteConfig | None"
) -> set[str]:
    excluded = set(_DEFAULT_EXCLUDED_HEADERS)
    if config is not None:
        excluded |= {h.lower() for h in config.excluded_detection_headers}
    if route_config is not None and route_config.excluded_detection_headers is not None:
        excluded |= {h.lower() for h in route_config.excluded_detection_headers}
    return excluded


def _resolve_log_level(config: "SecurityConfig | None") -> str | None:
    return config.log_suspicious_level if config is not None else "WARNING"


_DEFAULT_MAX_SCAN_VALUES = 512


def _resolve_max_scan_values(config: "SecurityConfig | None") -> int:
    return (
        config.detection_max_scan_values
        if config is not None
        else _DEFAULT_MAX_SCAN_VALUES
    )


_DEFAULT_MAX_SCAN_BYTES = 65536


def _resolve_max_scan_bytes(config: "SecurityConfig | None") -> int:
    return (
        config.detection_max_scan_bytes
        if config is not None
        else _DEFAULT_MAX_SCAN_BYTES
    )


_DEFAULT_MAX_JSON_DEPTH = 32


def _resolve_max_json_depth(config: "SecurityConfig | None") -> int:
    return (
        config.detection_max_json_depth
        if config is not None
        else _DEFAULT_MAX_JSON_DEPTH
    )
