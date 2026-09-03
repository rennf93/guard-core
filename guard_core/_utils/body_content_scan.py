from guard_core._utils.body_form_scan import (
    _multipart_part_entries,
    _multipart_text_parts,
    _scan_form_body,
    _scan_multipart_body,
    _scan_multipart_part,
)
from guard_core._utils.body_json_scan import (
    _MONGO_OPERATOR_KEY_RE,
    _mongo_operator_key_hit,
    _redact_sensitive_json,
    _scan_capped_json_subtree,
    _scan_json_container_frame,
    _scan_json_content,
    _scan_json_dict_entry_key,
    _scan_json_entry_frame,
    _scan_json_value,
)
from guard_core._utils.detection_scan import (
    _check_always_scan_header,
    _check_request_component,
    _log_detected_component,
    _scan_component_name,
)
from guard_core._utils.request_logging import redact_blob_for_display
from guard_core.protocols.request_protocol import GuardRequest

__all__ = [
    "_MONGO_OPERATOR_KEY_RE",
    "_mongo_operator_key_hit",
    "_multipart_part_entries",
    "_multipart_text_parts",
    "_redact_sensitive_json",
    "_scan_blob_body",
    "_scan_body_field",
    "_scan_capped_json_subtree",
    "_scan_excluded_header_component",
    "_scan_form_body",
    "_scan_headers",
    "_scan_json_container_frame",
    "_scan_json_content",
    "_scan_json_dict_entry_key",
    "_scan_json_entry_frame",
    "_scan_json_value",
    "_scan_multipart_body",
    "_scan_multipart_part",
    "_scan_normal_header_component",
    "_scan_query_param_value",
    "_scan_query_params",
    "_scan_request_body",
    "_scan_sensitive_header",
]


async def _scan_query_param_value(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str],
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    is_sensitive = key.lower() in sensitive_params
    detected, trigger, threats = await _check_request_component(
        value,
        f"query_param:{key}",
        f"query param '{key}'",
        client_ip,
        correlation_id,
        enabled_categories,
        None if is_sensitive else log_level,
        content_preview="[REDACTED]" if is_sensitive else None,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
    )
    if detected and is_sensitive:
        _log_detected_component(
            "[REDACTED]", f"query param '{key}'", client_ip, log_level
        )
    return detected, trigger, threats


async def _scan_query_params(
    request: GuardRequest,
    excluded_params: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    for key, value in request.query_params.items():
        if key.lower() in excluded_params:
            continue
        detected, trigger, threats = await _scan_component_name(
            key,
            f"query_param:{key}",
            f"query param name '{key}'",
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if detected:
            return True, f"Query param name '{key}': {trigger}", threats
        detected, trigger, threats = await _scan_query_param_value(
            key,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_params,
            sensitive_body_fields,
            excluded_body_fields,
        )
        if detected:
            return True, f"Query param '{key}': {trigger}", threats
    return False, "", []


def _scan_excluded_header_component(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    if enabled_categories is not None and "cmd_injection" not in enabled_categories:
        return None
    detected, trigger, threats = _check_always_scan_header(key)
    if detected:
        _log_detected_component(key, f"header name '{key}'", client_ip, log_level)
        return True, f"Header name '{key}': {trigger}", threats
    detected, trigger, threats = _check_always_scan_header(value)
    if detected:
        _log_detected_component(value, f"header '{key}'", client_ip, log_level)
        return True, f"Header '{key}': {trigger}", threats
    return None


async def _scan_normal_header_component(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    content_preview: str | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]] | None:
    detected, trigger, threats = await _scan_component_name(
        key,
        f"header:{key}",
        f"header name '{key}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if detected:
        return True, f"Header name '{key}': {trigger}", threats
    detected, trigger, threats = await _check_request_component(
        value,
        f"header:{key}",
        f"header '{key}'",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        content_preview=content_preview,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
    )
    if detected:
        return True, f"Header '{key}': {trigger}", threats
    return None


async def _scan_sensitive_header(
    key: str,
    value: str,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]] | None:
    if key.strip().lower() in excluded_headers:
        hit = _scan_excluded_header_component(
            key, value, enabled_categories, client_ip, None
        )
    else:
        hit = await _scan_normal_header_component(
            key,
            value,
            enabled_categories,
            client_ip,
            correlation_id,
            None,
            content_preview="[REDACTED]",
            sensitive_body_fields=sensitive_body_fields,
            excluded_body_fields=excluded_body_fields,
        )
    if hit is not None:
        _log_detected_component("[REDACTED]", f"header '{key}'", client_ip, log_level)
    return hit


async def _scan_headers(
    request: GuardRequest,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_headers: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    for key, value in request.headers.items():
        if key.strip().lower() in sensitive_headers:
            hit = await _scan_sensitive_header(
                key,
                value,
                excluded_headers,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
                sensitive_body_fields,
                excluded_body_fields,
            )
        elif key.strip().lower() in excluded_headers:
            hit = _scan_excluded_header_component(
                key, value, enabled_categories, client_ip, log_level
            )
        else:
            hit = await _scan_normal_header_component(
                key,
                value,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
                sensitive_body_fields=sensitive_body_fields,
                excluded_body_fields=excluded_body_fields,
            )
        if hit is not None:
            return hit
    return False, "", []


async def _scan_body_field(
    value: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    display: str | None = None,
    context: str = "request_body",
    preview_override: str | None = None,
) -> tuple[bool, str, list[dict]]:
    is_sensitive = label.lower() in sensitive_body_fields
    log_value = (
        preview_override
        if preview_override is not None
        else ("[REDACTED]" if is_sensitive else display)
    )
    detected, trigger, threats = await _check_request_component(
        value,
        context,
        label,
        client_ip,
        correlation_id,
        enabled_categories,
        None if log_value is not None else log_level,
        content_preview=log_value,
    )
    if not detected:
        return False, "", []
    if log_value is not None:
        _log_detected_component(log_value, label, client_ip, log_level)
    return True, f"Request body field '{label}': {trigger}", threats


async def _scan_blob_body(
    raw_body: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_params: frozenset[str] = frozenset(),
    sensitive_body_fields: frozenset[str] = frozenset(),
    force_redacted: bool = False,
) -> tuple[bool, str, list[dict]]:
    content_preview = (
        "[REDACTED]"
        if force_redacted
        else redact_blob_for_display(raw_body, sensitive_params, sensitive_body_fields)
    )
    detected, trigger, threats = await _check_request_component(
        raw_body,
        "request_body",
        "request body",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        content_preview=content_preview,
    )
    if detected:
        return True, f"Request body: {trigger}", threats
    return False, "", []


async def _scan_request_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        return await _scan_form_body(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
        )
    if "multipart/form-data" in lowered:
        return await _scan_multipart_body(
            raw_body,
            content_type,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
        )

    if "json" in lowered:
        json_hit = await _scan_json_content(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
        )
        if json_hit is not None:
            return json_hit
    return await _scan_blob_body(
        raw_body,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_params,
        sensitive_body_fields,
    )
