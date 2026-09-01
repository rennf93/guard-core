import inspect
import logging
from collections.abc import Callable
from typing import Any

from guard_core._utils.ip_extraction import UNKNOWN_CLIENT_IDENTITY, _canonicalize_ip
from guard_core.protocols.request_protocol import GuardRequest

logger = logging.getLogger("guard_core")

ON_BLOCK_EXCLUDED_CHECK_NAMES = frozenset(
    {"custom_request", "custom_validators", "https_enforcement"}
)


async def invoke_block_hook(
    hook: Callable[[GuardRequest, dict[str, Any]], Any] | None,
    request: GuardRequest,
    payload: dict[str, Any],
) -> None:
    if hook is None:
        return
    try:
        result = hook(request, payload)
        if inspect.isawaitable(result):
            await result
    except Exception as hook_error:
        logger.error(f"on_block hook raised: {hook_error}")


def build_block_payload(
    request: GuardRequest,
    check_name: str,
    reason: str,
    trigger_info: str,
    passive_mode: bool,
    status_code: int | None,
) -> dict[str, Any]:
    cached_ip = getattr(request.state, "client_ip", None)
    if cached_ip:
        client_ip = cached_ip
    elif request.client_host:
        client_ip = _canonicalize_ip(request.client_host)
    else:
        client_ip = UNKNOWN_CLIENT_IDENTITY

    return {
        "check_name": check_name,
        "reason": reason,
        "trigger_info": trigger_info,
        "passive_mode": passive_mode,
        "client_ip": client_ip,
        "path": request.url_path,
        "method": request.method,
        "status_code": status_code,
    }


async def fire_block_hook(
    hook: Callable[[GuardRequest, dict[str, Any]], Any] | None,
    request: GuardRequest,
    check_name: str,
    reason: str,
    trigger_info: str,
    passive_mode: bool,
    status_code: int | None,
) -> None:
    if hook is None or check_name in ON_BLOCK_EXCLUDED_CHECK_NAMES:
        return
    payload = build_block_payload(
        request, check_name, reason, trigger_info, passive_mode, status_code
    )
    await invoke_block_hook(hook, request, payload)
