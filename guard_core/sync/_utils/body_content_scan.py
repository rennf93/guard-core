import json
import re
from typing import Any

from guard_core.sync._utils.detection_scan import (
    _check_always_scan_header,
    _check_request_component,
    _json_depth_cap_value,
    _log_detected_component,
    _scan_component_name,
    _warn_json_depth_cap_reached_once,
)
from guard_core.sync._utils.logging_utils import _sanitize_for_reporting
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def _scan_query_params(
    request: SyncGuardRequest,
    excluded_params: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    for key, value in request.query_params.items():
        if key.lower() in excluded_params:
            continue
        detected, trigger, threats = _scan_component_name(
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
        detected, trigger, threats = _check_request_component(
            value,
            f"query_param:{key}",
            f"query param '{key}'",
            client_ip,
            correlation_id,
            enabled_categories,
            log_level,
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


def _scan_normal_header_component(
    key: str,
    value: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    detected, trigger, threats = _scan_component_name(
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
    detected, trigger, threats = _check_request_component(
        value,
        f"header:{key}",
        f"header '{key}'",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
    )
    if detected:
        return True, f"Header '{key}': {trigger}", threats
    return None


def _scan_headers(
    request: SyncGuardRequest,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    for key, value in request.headers.items():
        if key.lower() in excluded_headers:
            hit = _scan_excluded_header_component(
                key, value, enabled_categories, client_ip, log_level
            )
        else:
            hit = _scan_normal_header_component(
                key, value, enabled_categories, client_ip, correlation_id, log_level
            )
        if hit is not None:
            return hit
    return False, "", []


def _scan_body_field(
    value: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = _check_request_component(
        value,
        "request_body",
        label,
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
    )
    if detected:
        return True, f"Request body field '{label}': {trigger}", threats
    return False, "", []


def _scan_blob_body(
    raw_body: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = _check_request_component(
        raw_body,
        "request_body",
        "request body",
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
    )
    if detected:
        return True, f"Request body: {trigger}", threats
    return False, "", []


_MONGO_OPERATOR_KEY_RE = re.compile(
    r"^\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|"
    r"mod|options|where|regex|expr|function|elemMatch)$"
)


def _mongo_operator_key_hit(key_str: str) -> tuple[bool, str, list[dict]]:
    threat = {
        "type": "regex",
        "pattern": _MONGO_OPERATOR_KEY_RE.pattern,
        "match": _sanitize_for_reporting(key_str),
        "position": 0,
        "category": "nosql",
    }
    return (
        True,
        f"JSON operator key '{key_str}': matched pattern "
        f"'{_MONGO_OPERATOR_KEY_RE.pattern}'",
        [threat],
    )


def _scan_json_dict_entry_key(
    key: Any,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    key_str = str(key)
    if key_str.lower() in excluded_body_fields:
        return None
    if _MONGO_OPERATOR_KEY_RE.match(key_str):
        return _mongo_operator_key_hit(key_str)
    name_hit = _scan_component_name(
        key_str,
        "request_body",
        f"JSON key '{key_str}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if name_hit[0]:
        return True, f"JSON key '{key_str}': {name_hit[1]}", name_hit[2]
    return False, "", []


def _scan_capped_json_subtree(
    value: Any,
    key_label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    _warn_json_depth_cap_reached_once(client_ip)
    serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return _scan_body_field(
        serialized, key_label, enabled_categories, client_ip, correlation_id, log_level
    )


def _scan_json_container_frame(
    current: Any,
    label: str,
    depth: int,
    max_depth: int,
    stack: list[tuple[str, Any, Any, int]],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    if depth >= max_depth:
        hit = _scan_capped_json_subtree(
            current, label, enabled_categories, client_ip, correlation_id, log_level
        )
        return hit if hit[0] else None
    if isinstance(current, dict):
        for key, item in reversed(list(current.items())):
            stack.append(("entry", key, item, depth))
        return None
    for item in reversed(current):
        stack.append(("value", item, label, depth + 1))
    return None


def _scan_json_entry_frame(
    key: Any,
    item: Any,
    depth: int,
    stack: list[tuple[str, Any, Any, int]],
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    key_result = _scan_json_dict_entry_key(
        key,
        excluded_body_fields,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if key_result is None:
        return None
    if key_result[0]:
        return key_result
    stack.append(("value", item, str(key), depth + 1))
    return None


def _scan_json_value(
    value: Any,
    key_label: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    max_depth = _json_depth_cap_value()
    stack: list[tuple[str, Any, Any, int]] = [("value", value, key_label, 1)]
    while stack:
        kind, first, second, depth = stack.pop()
        if kind == "entry":
            hit = _scan_json_entry_frame(
                first,
                second,
                depth,
                stack,
                excluded_body_fields,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
            )
            if hit is not None:
                return hit
            continue
        current, label = first, second
        if isinstance(current, dict | list):
            hit = _scan_json_container_frame(
                current,
                label,
                depth,
                max_depth,
                stack,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
            )
            if hit is not None:
                return hit
            continue
        scalar_hit = _scan_body_field(
            str(current),
            label,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if scalar_hit[0]:
            return scalar_hit
    return False, "", []


def _scan_form_body(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    from urllib.parse import parse_qsl

    for name, value in parse_qsl(
        raw_body, keep_blank_values=True, errors="surrogateescape"
    ):
        if name.lower() in excluded_body_fields:
            continue
        name_hit = _scan_component_name(
            name,
            "request_body",
            f"form field name '{name}'",
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if name_hit[0]:
            return True, f"Form field name '{name}': {name_hit[1]}", name_hit[2]
        hit = _scan_body_field(
            value, name, enabled_categories, client_ip, correlation_id, log_level
        )
        if hit[0]:
            return hit
    return False, "", []


def _multipart_part_entries(part: Any) -> list[tuple[str | None, str, str]]:
    entries: list[tuple[str | None, str, str]] = []
    name = part.get_param("name", header="content-disposition")
    filename = part.get_filename()
    exclusion_key = str(name) if name is not None else None
    label = exclusion_key if exclusion_key is not None else "file"
    if filename is not None:
        sanitized_filename = filename.replace('"', "").replace("'", "")
        entries.append((exclusion_key, label, f'filename="{sanitized_filename}"'))
    payload = getattr(part, "_payload", None)
    if isinstance(payload, str):
        entries.append((exclusion_key, label, payload))
    return entries


def _multipart_text_parts(
    raw_body: str, content_type: str
) -> list[tuple[str | None, str, str]] | None:
    from email.parser import Parser
    from email.policy import compat32

    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    message = Parser(policy=compat32).parsestr(header + raw_body)
    if not message.is_multipart():
        return None
    parts: list[tuple[str | None, str, str]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        parts.extend(_multipart_part_entries(part))
    return parts


def _scan_multipart_part(
    exclusion_key: str | None,
    label: str,
    value: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    if exclusion_key is not None and exclusion_key.lower() in excluded_body_fields:
        return None
    name_hit = _scan_component_name(
        label,
        "request_body",
        f"multipart field name '{label}'",
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if name_hit[0]:
        return True, f"Multipart field name '{label}': {name_hit[1]}", name_hit[2]
    hit = _scan_body_field(
        value, label, enabled_categories, client_ip, correlation_id, log_level
    )
    if hit[0]:
        return hit
    return None


def _scan_multipart_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    parts = _multipart_text_parts(raw_body, content_type)
    if parts is None:
        return _scan_blob_body(
            raw_body, enabled_categories, client_ip, correlation_id, log_level
        )
    for exclusion_key, label, value in parts:
        hit = _scan_multipart_part(
            exclusion_key,
            label,
            value,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if hit is not None:
            return hit
    return False, "", []


def _scan_json_content(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]] | None:
    try:
        parsed_body = json.loads(raw_body)
    except Exception:
        parsed_body = None
    if isinstance(parsed_body, dict | list):
        return _scan_json_value(
            parsed_body,
            "",
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
    return None


def _scan_request_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        return _scan_form_body(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
    if "multipart/form-data" in lowered:
        return _scan_multipart_body(
            raw_body,
            content_type,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )

    if "json" in lowered:
        json_hit = _scan_json_content(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if json_hit is not None:
            return json_hit
    return _scan_blob_body(
        raw_body, enabled_categories, client_ip, correlation_id, log_level
    )
