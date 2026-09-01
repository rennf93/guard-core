import logging
from collections.abc import Callable
from typing import Any, Literal

from guard_core.sync._utils.block_events import fire_block_hook
from guard_core.sync._utils.ip_extraction import (
    UNKNOWN_CLIENT_IDENTITY,
    _canonicalize_ip,
)
from guard_core.sync._utils.logging_utils import _log_at_level
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def _extract_request_context(request: SyncGuardRequest) -> dict[str, Any]:
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
        "url": request.url_full,
        "headers": dict(request.headers),
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

    context = _extract_request_context(request)

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
