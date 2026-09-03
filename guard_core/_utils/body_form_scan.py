from typing import Any

from guard_core._utils.detection_scan import _scan_component_name


async def _scan_form_body(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    from urllib.parse import parse_qsl

    from guard_core._utils.body_content_scan import _scan_body_field

    for name, value in parse_qsl(
        raw_body, keep_blank_values=True, errors="surrogateescape"
    ):
        if name.lower() in excluded_body_fields:
            continue
        name_hit = await _scan_component_name(
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
        hit = await _scan_body_field(
            value,
            name,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
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


async def _scan_multipart_part(
    exclusion_key: str | None,
    label: str,
    value: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]] | None:
    from guard_core._utils.body_content_scan import _scan_body_field

    if exclusion_key is not None and exclusion_key.lower() in excluded_body_fields:
        return None
    name_hit = await _scan_component_name(
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
    hit = await _scan_body_field(
        value,
        label,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
        sensitive_body_fields,
    )
    if hit[0]:
        return hit
    return None


async def _scan_multipart_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    sensitive_body_fields: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    from guard_core._utils.body_content_scan import _scan_blob_body

    parts = _multipart_text_parts(raw_body, content_type)
    if parts is None:
        return await _scan_blob_body(
            raw_body, enabled_categories, client_ip, correlation_id, log_level
        )
    for exclusion_key, label, value in parts:
        hit = await _scan_multipart_part(
            exclusion_key,
            label,
            value,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
            sensitive_body_fields,
        )
        if hit is not None:
            return hit
    return False, "", []
