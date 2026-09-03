import json
import logging
import re
from collections.abc import Callable
from typing import Any, Literal
from urllib.parse import quote, quote_plus, unquote, unquote_plus, urlsplit, urlunsplit

from guard_core.sync._utils.block_events import fire_block_hook
from guard_core.sync._utils.ip_extraction import (
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
)
from guard_core.sync._utils.logging_utils import _log_at_level, _redact_sensitive_json
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

_DEFAULT_SENSITIVE_LOG_HEADERS: frozenset[str] = frozenset(
    {"authorization", "proxy-authorization", "cookie", "x-api-key"}
)

_DEFAULT_SENSITIVE_LOG_FIELDS: frozenset[str] = frozenset(
    {
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "token",
        "password",
        "secret",
        "client_secret",
        "signature",
    }
)


def _merge_sensitive_names(
    defaults: frozenset[str], extra: frozenset[str] | None
) -> frozenset[str]:
    if extra is None:
        return defaults
    return defaults | {name.lower() for name in extra}


def _merge_sensitive_log_headers(extra: frozenset[str] | None) -> frozenset[str]:
    return _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_HEADERS, extra)


_MAX_DECODE_ROUNDS = 3


def _bounded_percent_decode(
    text: str, decode_fn: Callable[[str], str] = unquote_plus
) -> str:
    decoded = text
    for _ in range(_MAX_DECODE_ROUNDS):
        next_decoded = decode_fn(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return decoded


def _resolve_json_depth_cap() -> int:
    from guard_core.sync._utils.detection_scan import _json_depth_cap_value

    return _json_depth_cap_value()


def _json_redact_text(
    text: str, sensitive_body_fields: frozenset[str], max_depth: int
) -> str | None:
    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict | list):
            return None
        redacted = _redact_sensitive_json(parsed, sensitive_body_fields, max_depth)
        if redacted == parsed:
            return None
        return json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
    except RecursionError:
        return "[REDACTED]"
    except ValueError:
        return None


def _redact_embedded_json_value(
    value: str, sensitive_body_fields: frozenset[str], max_depth: int
) -> str:
    decoded = _bounded_percent_decode(value)
    redacted_text = _json_redact_text(decoded, sensitive_body_fields, max_depth)
    return value if redacted_text is None else redacted_text


def _redact_path_segment(
    segment: str,
    sensitive_body_fields: frozenset[str],
    sensitive: frozenset[str],
    max_depth: int,
) -> str:
    proper, sep, rest = segment.partition(";")
    decoded = _bounded_percent_decode(proper, unquote)
    redacted_text = _json_redact_text(decoded, sensitive_body_fields, max_depth)
    redacted_proper = proper if redacted_text is None else quote(redacted_text, safe="")
    if not sep:
        return redacted_proper
    redacted_matrix_parts = (
        _redact_sensitive_query_pair(part, sensitive, sensitive_body_fields, max_depth)
        for part in rest.split(";")
    )
    return ";".join([redacted_proper, *redacted_matrix_parts])


def _redact_sensitive_path(
    path: str,
    sensitive_body_fields: frozenset[str],
    sensitive: frozenset[str],
    max_depth: int,
) -> str:
    return "/".join(
        _redact_path_segment(segment, sensitive_body_fields, sensitive, max_depth)
        for segment in path.split("/")
    )


def _merge_sensitive_log_body_fields(extra: frozenset[str] | None) -> frozenset[str]:
    return _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, extra)


def _redact_sensitive_headers(
    headers: dict[str, str],
    sensitive_headers: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
) -> dict[str, str]:
    sensitive = _merge_sensitive_log_headers(sensitive_headers)
    body_fields = _merge_sensitive_log_body_fields(sensitive_body_fields)
    max_depth = _resolve_json_depth_cap()
    return {
        key: "[REDACTED]"
        if key.lower() in sensitive
        else _redact_embedded_json_value(value, body_fields, max_depth)
        for key, value in headers.items()
    }


_SMUGGLED_PAIR_SEPARATOR_RE = re.compile(r"[&;?]")


def _redact_percent_encoded_pair(pair: str, sensitive: frozenset[str]) -> str:
    decoded = _bounded_percent_decode(pair)
    for token in _SMUGGLED_PAIR_SEPARATOR_RE.split(decoded):
        name, eq, _ = token.partition("=")
        if eq and name.lower() in sensitive:
            return "[REDACTED]"
    return pair


def _redact_sensitive_query_pair(
    pair: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    if "=" not in pair:
        return _redact_percent_encoded_pair(pair, sensitive)
    name, _, value = pair.partition("=")
    if unquote_plus(name).lower() in sensitive:
        return f"{name}=[REDACTED]"
    redacted_value = _redact_embedded_json_value(
        value, sensitive_body_fields, max_depth
    )
    if redacted_value == value:
        return pair
    return f"{name}={quote_plus(redacted_value)}"


_QUERY_PAIR_SEPARATOR_RE = re.compile(r"([&;])")


def _redact_query_string(
    query: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    tokens = _QUERY_PAIR_SEPARATOR_RE.split(query)
    return "".join(
        token
        if token in ("&", ";")
        else _redact_sensitive_query_pair(
            token, sensitive, sensitive_body_fields, max_depth
        )
        for token in tokens
    )


_FRAGMENT_PAIR_SEPARATOR_RE = re.compile(r"([?&;])")


def _redact_fragment_query_string(
    fragment: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    tokens = _FRAGMENT_PAIR_SEPARATOR_RE.split(fragment)
    return "".join(
        token
        if token in ("?", "&", ";")
        else _redact_sensitive_query_pair(
            token, sensitive, sensitive_body_fields, max_depth
        )
        for token in tokens
    )


def _redact_netloc_password(netloc: str) -> str:
    if "@" not in netloc:
        return netloc
    userinfo, _, hostport = netloc.rpartition("@")
    if ":" not in userinfo:
        return netloc
    user, _, _ = userinfo.partition(":")
    return f"{user}:[REDACTED]@{hostport}"


def _redact_sensitive_query_params(
    url: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
) -> str:
    parts = urlsplit(url)
    body_fields = _merge_sensitive_log_body_fields(sensitive_body_fields)
    sensitive = _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, sensitive_params)
    max_depth = _resolve_json_depth_cap()
    redacted_path = _redact_sensitive_path(
        parts.path, body_fields, sensitive, max_depth
    )
    if (
        not parts.query
        and not parts.fragment
        and "@" not in parts.netloc
        and redacted_path == parts.path
    ):
        return url
    redacted_query = (
        _redact_query_string(parts.query, sensitive, body_fields, max_depth)
        if parts.query
        else parts.query
    )
    redacted_fragment = (
        _redact_fragment_query_string(parts.fragment, sensitive, body_fields, max_depth)
        if parts.fragment
        else parts.fragment
    )
    return urlunsplit(
        (
            parts.scheme,
            _redact_netloc_password(parts.netloc),
            redacted_path,
            redacted_query,
            redacted_fragment,
        )
    )


def _extract_request_context(
    request: SyncGuardRequest,
    sensitive_headers: frozenset[str] | None,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
) -> dict[str, Any]:
    cached_ip = getattr(request.state, "client_ip", None)
    if cached_ip:
        client_ip = cached_ip
    elif request.client_host:
        client_ip = _canonicalize_ip(request.client_host)
    else:
        client_ip = UNKNOWN_CLIENT_IDENTITY

    return {
        "client_ip": client_ip,
        "method": request.method,
        "url": _redact_sensitive_query_params(
            request.url_full, sensitive_params, sensitive_body_fields
        ),
        "headers": _redact_sensitive_headers(
            dict(request.headers), sensitive_headers, sensitive_body_fields
        ),
    }


def _build_log_message_for_request(context: dict[str, Any]) -> tuple[str, str]:
    message = "Request from"
    details = f"{message} {context['client_ip']}: {context['method']} {context['url']}"
    reason_message = f"Headers: {context['headers']}"
    return details, reason_message


def _build_log_message_for_suspicious(
    context: dict[str, Any], reason: str, passive_mode: bool, trigger_info: str
) -> tuple[str, str]:
    if passive_mode:
        message = "[PASSIVE MODE] Penetration attempt detected from"
        details = (
            f"{message} {context['client_ip']}: {context['method']} {context['url']}"
        )

        trigger_message = f"Trigger: {trigger_info}" if trigger_info else ""
        reason_message = f"Headers: {context['headers']}"
        if trigger_message:
            reason_message = f"{trigger_message} - {reason_message}"
    else:
        message = "Suspicious activity detected from"
        details = (
            f"{message} {context['client_ip']}: {context['method']} {context['url']}"
        )
        reason_message = f"Reason: {reason} - Headers: {context['headers']}"

    return details, reason_message


def _build_log_message_generic(
    context: dict[str, Any], log_type: str, reason: str
) -> tuple[str, str]:
    message = f"{log_type.capitalize()} from"
    details = f"{message} {context['client_ip']}: {context['method']} {context['url']}"
    reason_message = f"Details: {reason} - Headers: {context['headers']}"
    return details, reason_message


def _dispatch_block_hook(
    request: SyncGuardRequest,
    log_type: str,
    check_name: str | None,
    reason: str,
    trigger_info: str,
    passive_mode: bool,
    on_block: Callable[[SyncGuardRequest, dict[str, Any]], Any] | None,
) -> None:
    if log_type != "suspicious":
        return
    if not passive_mode:
        request.state._guard_block_stash = {
            "reason": reason,
            "trigger_info": trigger_info,
        }
        return
    fire_block_hook(
        on_block, request, check_name or "", reason, trigger_info, True, None
    )


def log_activity(
    request: SyncGuardRequest,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING",
    check_name: str | None = None,
    muted_check_logs: frozenset[str] | None = None,
    on_block: Callable[[SyncGuardRequest, dict[str, Any]], Any] | None = None,
    sensitive_headers: frozenset[str] | None = None,
    sensitive_params: frozenset[str] | None = None,
    sensitive_body_fields: frozenset[str] | None = None,
) -> None:
    _dispatch_block_hook(
        request, log_type, check_name, reason, trigger_info, passive_mode, on_block
    )
    if level is None:
        return
    if (
        check_name is not None
        and muted_check_logs is not None
        and check_name in muted_check_logs
    ):
        return

    context = _extract_request_context(
        request, sensitive_headers, sensitive_params, sensitive_body_fields
    )

    if log_type == "request":
        details, reason_message = _build_log_message_for_request(context)
    elif log_type == "suspicious":
        details, reason_message = _build_log_message_for_suspicious(
            context, reason, passive_mode, trigger_info
        )
    else:
        details, reason_message = _build_log_message_generic(context, log_type, reason)

    msg = f"{details} - {reason_message}"
    _log_at_level(logger, level, msg)
