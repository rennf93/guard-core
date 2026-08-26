from typing import TYPE_CHECKING

from guard_core.sync._utils.body_content_scan import (
    _scan_headers,
    _scan_query_params,
    _scan_request_body,
)
from guard_core.sync._utils.body_reader import _read_capped_body
from guard_core.sync._utils.detection_config import (
    _resolve_enabled_categories,
    _resolve_excluded_body_fields,
    _resolve_excluded_headers,
    _resolve_excluded_params,
    _resolve_log_level,
    _resolve_max_json_depth,
    _resolve_max_scan_values,
    _resolve_scan_body,
)
from guard_core.sync._utils.detection_result_builders import (
    _build_detection_hit,
    _build_detection_miss,
)
from guard_core.sync._utils.detection_scan import (
    _check_request_component,
    _scan_value_budget,
)
from guard_core.sync._utils.ip_extraction import (
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
    extract_client_ip,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.sync.decorators.base import RouteConfig


def _scan_request_surface(
    request: SyncGuardRequest,
    excluded_params: set[str],
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> DetectionResult | None:
    detected, trigger, threats = _scan_query_params(
        request,
        excluded_params,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    detected, trigger, threats = _check_request_component(
        request.url_path,
        "url_path",
        "URL path",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
    )
    if detected:
        return _build_detection_hit(f"URL path: {trigger}", threats)

    detected, trigger, threats = _scan_headers(
        request,
        excluded_headers,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    return None


def _scan_body_surface(
    request: SyncGuardRequest,
    config: "SecurityConfig | None",
    route_config: "RouteConfig | None",
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> DetectionResult:
    if not _resolve_scan_body(config, route_config):
        return _build_detection_miss()

    body_bytes = _read_capped_body(request, config)
    if body_bytes is None:
        return _build_detection_miss()

    raw_body = body_bytes.decode("utf-8", errors="surrogateescape")

    content_type = request.headers.get("content-type") or ""
    detected, trigger, threats = _scan_request_body(
        raw_body,
        content_type,
        excluded_body_fields,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if detected:
        return _build_detection_hit(trigger, threats)
    return _build_detection_miss()


def detect_penetration_attempt(
    request: SyncGuardRequest,
    config: "SecurityConfig | None" = None,
    route_config: "RouteConfig | None" = None,
) -> DetectionResult:
    import uuid

    if config is not None:
        client_ip = extract_client_ip(request, config)
    else:
        client_ip = (
            _canonicalize_ip(request.client_host)
            if request.client_host
            else UNKNOWN_CLIENT_IDENTITY
        )
    correlation_id = str(uuid.uuid4())

    excluded_params = _resolve_excluded_params(config, route_config)
    excluded_body_fields = _resolve_excluded_body_fields(config, route_config)
    enabled_categories = _resolve_enabled_categories(config, route_config)
    excluded_headers = _resolve_excluded_headers(config, route_config)
    log_level = _resolve_log_level(config)
    max_scan_values = _resolve_max_scan_values(config)
    max_json_depth = _resolve_max_json_depth(config)

    with _scan_value_budget(max_scan_values, max_json_depth):
        surface_hit = _scan_request_surface(
            request,
            excluded_params,
            excluded_headers,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if surface_hit is not None:
            return surface_hit

        return _scan_body_surface(
            request,
            config,
            route_config,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
