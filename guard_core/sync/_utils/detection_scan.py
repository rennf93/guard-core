import contextvars
import logging
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from guard_core.sync._utils.detection_config import (
    _DEFAULT_MAX_JSON_DEPTH,
    _DEFAULT_MAX_SCAN_CHARS,
    _DEFAULT_MAX_SCAN_VALUES,
)
from guard_core.sync._utils.logging_utils import _log_at_level, _sanitize_for_reporting

logger = logging.getLogger("guard_core")

_scanned_value_count: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scanned_value_count", default=0
)
_scan_value_cap: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scan_value_cap", default=_DEFAULT_MAX_SCAN_VALUES
)
_scanned_char_count: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scanned_char_count", default=0
)
_scan_char_cap: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scan_char_cap", default=_DEFAULT_MAX_SCAN_CHARS
)
_scan_char_cap_warned: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_detection_scan_char_cap_warned", default=False
)
_json_depth_cap: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_json_depth_cap", default=_DEFAULT_MAX_JSON_DEPTH
)
_json_depth_warned: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_detection_json_depth_warned", default=False
)


@contextmanager
def _scan_value_budget(
    max_values: int,
    max_json_depth: int = _DEFAULT_MAX_JSON_DEPTH,
    max_scan_chars: int = _DEFAULT_MAX_SCAN_CHARS,
) -> Iterator[None]:
    count_token = _scanned_value_count.set(0)
    cap_token = _scan_value_cap.set(max_values)
    char_count_token = _scanned_char_count.set(0)
    char_cap_token = _scan_char_cap.set(max_scan_chars)
    char_warned_token = _scan_char_cap_warned.set(False)
    depth_cap_token = _json_depth_cap.set(max_json_depth)
    depth_warned_token = _json_depth_warned.set(False)
    try:
        yield
    finally:
        _scanned_value_count.reset(count_token)
        _scan_value_cap.reset(cap_token)
        _scanned_char_count.reset(char_count_token)
        _scan_char_cap.reset(char_cap_token)
        _scan_char_cap_warned.reset(char_warned_token)
        _json_depth_cap.reset(depth_cap_token)
        _json_depth_warned.reset(depth_warned_token)


def _scan_value_budget_exhausted(client_ip: str) -> bool:
    count = _scanned_value_count.get() + 1
    _scanned_value_count.set(count)
    cap = _scan_value_cap.get()
    if count <= cap:
        return False
    if count == cap + 1:
        logger.warning(
            "detection_max_scan_values (%d) reached for client %s; remaining "
            "request values are not scanned",
            cap,
            client_ip,
        )
    return True


def _scan_char_budget_exhausted(client_ip: str, value_length: int) -> bool:
    consumed_before = _scanned_char_count.get()
    cap = _scan_char_cap.get()
    if consumed_before >= cap:
        if not _scan_char_cap_warned.get():
            _scan_char_cap_warned.set(True)
            logger.warning(
                "detection_max_scan_chars (%d) reached for client %s; remaining "
                "request values are not scanned",
                cap,
                client_ip,
            )
        return True
    _scanned_char_count.set(consumed_before + value_length)
    return False


def _scan_budget_exhausted(client_ip: str, value: str) -> bool:
    if _scan_value_budget_exhausted(client_ip):
        return True
    return _scan_char_budget_exhausted(client_ip, len(value))


def _json_depth_cap_value() -> int:
    return _json_depth_cap.get()


def _warn_json_depth_cap_reached_once(client_ip: str) -> None:
    if _json_depth_warned.get():
        return
    _json_depth_warned.set(True)
    logger.warning(
        "detection_max_json_depth (%d) reached for client %s; nested content "
        "below that depth is scanned as text",
        _json_depth_cap.get(),
        client_ip,
    )


_PATTERN_SOURCE_NON_TOKEN_RE = re.compile(r"[^a-z0-9_-]+")
_PATTERN_SOURCE_ESCAPE_RE = re.compile(
    r"\\(?:[xX]([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([0-7]{1,3}))"
)


def _decode_pattern_source_escape(match: re.Match[str]) -> str:
    hex_body = match.group(1) or match.group(2) or match.group(3)
    code = int(hex_body, 16) if hex_body else int(match.group(4), 8)
    return chr(code) if code <= 0x10FFFF else match.group(0)


def _pattern_source_names_a_sensitive_field(
    pattern_source: str, sensitive_names: frozenset[str]
) -> bool:
    decoded = _PATTERN_SOURCE_ESCAPE_RE.sub(
        _decode_pattern_source_escape, pattern_source
    )
    normalized = _PATTERN_SOURCE_NON_TOKEN_RE.sub("", decoded.lower())
    return any(name in normalized for name in sensitive_names)


def _redact_pattern_source(pattern_source: str) -> str:
    from guard_core.sync._utils.request_logging import (
        _merge_sensitive_log_body_fields,
        _merged_sensitive_names,
        redact_blob_for_display,
    )
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    sensitive_params = sus_patterns_handler._sensitive_params_union
    sensitive_body_fields = sus_patterns_handler._sensitive_body_fields_union
    sensitive_headers = sus_patterns_handler._sensitive_headers_union

    sensitive_names = _merged_sensitive_names(
        sensitive_params,
        _merge_sensitive_log_body_fields(sensitive_body_fields),
        sensitive_headers,
    )
    if _pattern_source_names_a_sensitive_field(pattern_source, sensitive_names):
        return "[REDACTED]"

    return redact_blob_for_display(
        pattern_source, sensitive_params, sensitive_body_fields, sensitive_headers
    )


def _build_threat_message(threat: dict[str, Any]) -> str:
    if threat["type"] == "regex":
        return f"Value matched pattern '{_redact_pattern_source(threat['pattern'])}'"
    elif threat["type"] == "semantic":
        attack_type = threat.get("attack_type", "suspicious")
        score = threat.get("probability", threat.get("threat_score", 0))
        return f"Semantic attack: {attack_type} (score: {score:.2f})"
    elif threat["type"] == "pattern_timeout":
        return (
            f"Pattern exceeded scan time budget: "
            f"'{_redact_pattern_source(threat['pattern'])}'"
        )
    return "Threat detected"


_MAX_USER_AGENT_MATCH_LENGTH = 512


def _user_agent_matches_blocked_pattern(user_agent: str, patterns: list[str]) -> bool:
    from guard_core.sync.detection_engine.compiler import PatternCompiler

    subject = user_agent[:_MAX_USER_AGENT_MATCH_LENGTH]
    compiler = PatternCompiler()
    for pattern in patterns:
        finder = compiler.create_async_safe_finditer_matcher(pattern, inline_safe=True)
        if finder(subject):
            return True
    return False


def _fallback_pattern_check(
    value: str, client_ip: str, context: str
) -> tuple[bool, str]:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    normalized_context = sus_patterns_handler._normalize_context(context)
    all_compiled = sus_patterns_handler.get_all_compiled_patterns()
    for pattern, _contexts, category in all_compiled:
        pattern_start = time.monotonic()
        try:
            threat, _timeout_occurred = sus_patterns_handler._check_regex_pattern(
                pattern,
                value,
                client_ip,
                pattern_start,
                category,
                context=normalized_context,
            )
        except RecursionError:
            logger.warning(
                "Fallback pattern search hit the regex engine's recursion "
                "limit on pattern %r; skipping it and continuing the "
                "fallback scan",
                _redact_pattern_source(pattern.pattern),
            )
            continue
        if threat:
            return True, "Value matched pattern (fallback)"
    return False, ""


def _resolve_json_redact_all(
    content_preview: str | None, json_redact_all: bool | None
) -> bool:
    if json_redact_all is not None:
        return json_redact_all
    return content_preview is not None


def _check_embedded_json_if_applicable(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    scan_embedded_json: bool,
    content_preview: str | None,
    sensitive_body_fields: frozenset[str],
    excluded_body_fields: frozenset[str],
    json_redact_all: bool | None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict], str | None] | None:
    if not scan_embedded_json or context == "request_body":
        return None

    from guard_core.sync._utils.embedded_json_scan import _check_embedded_json

    json_result = _check_embedded_json(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        excluded_body_fields,
        sensitive_body_fields,
        redact_all=_resolve_json_redact_all(content_preview, json_redact_all),
        sensitive_params=sensitive_params,
    )
    if json_result is None or not json_result[0]:
        return None
    return json_result


def _check_value_enhanced(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
    scan_embedded_json: bool = True,
    content_preview: str | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    json_redact_all: bool | None = None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict], str | None]:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    if _scan_budget_exhausted(client_ip, value):
        return False, "", [], None

    json_hit = _check_embedded_json_if_applicable(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        scan_embedded_json,
        content_preview,
        sensitive_body_fields,
        excluded_body_fields,
        json_redact_all,
        sensitive_params,
    )
    if json_hit is not None:
        return json_hit

    try:
        result = sus_patterns_handler.detect(
            content=value,
            ip_address=client_ip,
            context=context,
            correlation_id=correlation_id,
            enabled_categories=enabled_categories,
            content_preview=content_preview,
        )

        if not result["is_threat"]:
            return False, "", [], None

        threats: list[dict] = list(result.get("threats", []))
        if threats:
            return True, _build_threat_message(threats[0]), threats, None

        return True, "Threat detected", threats, None

    except RecursionError:
        raise
    except Exception as e:
        logger.error(f"Enhanced detection failed: {e}, falling back to basic check")
        detected, trigger = _fallback_pattern_check(value, client_ip, context)
        return detected, trigger, [], None


def _log_detected_component(
    value: str, component_name: str, client_ip: str, log_level: str | None
) -> None:
    if log_level is None:
        return
    message = "Potential attack detected from"
    details = (
        f"{client_ip}: {value[:100]}..."
        if len(value) > 100
        else f"{client_ip}: {value}"
    )
    reason_message = f"Suspicious pattern in {component_name}"
    _log_at_level(logger, log_level, f"{message} {details} - {reason_message}")


def _check_request_component(
    value: str,
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    log_level: str | None,
    scan_embedded_json: bool = True,
    content_preview: str | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    json_redact_all: bool | None = None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats, log_override = _check_value_enhanced(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        scan_embedded_json,
        content_preview=content_preview,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        json_redact_all=json_redact_all,
        sensitive_params=sensitive_params,
    )
    if detected:
        fallback = content_preview if content_preview is not None else value
        _log_detected_component(
            log_override if log_override is not None else fallback,
            component_name,
            client_ip,
            log_level,
        )
    return detected, trigger, threats


def _scan_component_name(
    name: str,
    context: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    content_preview: str | None = None,
) -> tuple[bool, str, list[dict]]:
    return _check_request_component(
        name,
        context,
        label,
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        scan_embedded_json=False,
        content_preview=content_preview,
    )


def _check_always_scan_header(value: str) -> tuple[bool, str, list[dict]]:
    from guard_core.sync.handlers.suspatterns_handler import ALWAYS_SCAN_HEADER_PATTERNS

    for pattern in ALWAYS_SCAN_HEADER_PATTERNS:
        match = pattern.search(value)
        if match:
            threat = {
                "type": "regex",
                "pattern": pattern.pattern,
                "match": _sanitize_for_reporting(match.group()),
                "position": match.start(),
                "category": "cmd_injection",
            }
            trigger = (
                f"Value matched pattern '{_redact_pattern_source(pattern.pattern)}'"
            )
            return True, trigger, [threat]
    return False, "", []
