import logging
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any

from guard_core._utils.agent_events import send_agent_event
from guard_core._utils.logging_utils import _sanitize_for_log
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.request_protocol import GuardRequest

logger = logging.getLogger("guard_core")


def _proxy_matches(connecting_ip: str, connecting_ip_obj: Any, proxy: str) -> bool:
    if "/" in proxy:
        return connecting_ip_obj in ip_network(proxy, strict=False)
    return connecting_ip == proxy


def _is_trusted_proxy(connecting_ip: str, trusted_proxies: list[str]) -> bool:
    try:
        connecting_ip_obj = ip_address(connecting_ip)
        return any(
            _proxy_matches(connecting_ip, connecting_ip_obj, proxy)
            for proxy in trusted_proxies
        )
    except ValueError:
        return False


def _canonical_ip_text(addr: IPv4Address | IPv6Address) -> str:
    if (
        isinstance(addr, IPv6Address)
        and addr.ipv4_mapped is not None
        and addr.scope_id is None
    ):
        return str(addr.ipv4_mapped)
    return str(addr)


def _strip_ip_brackets(value: str) -> str:
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def _canonicalize_ip(value: str) -> str:
    try:
        addr = ip_address(_strip_ip_brackets(value))
    except ValueError:
        return value
    return _canonical_ip_text(addr)


def _forwarded_header_candidate_has_metachar(candidate: str) -> bool:
    return any(metachar in candidate for metachar in ("*", "?", "[", "]", "\\"))


def _forwarded_header_candidate(forwarded_for: str, proxy_depth: int) -> str | None:
    ips = [ip.strip() for ip in forwarded_for.split(",")]
    if len(ips) < proxy_depth:
        return None
    return _strip_ip_brackets(ips[-proxy_depth])


def _forwarded_header_candidate_addr(
    candidate: str,
) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(candidate)
    except ValueError:
        return None


def _extract_from_forwarded_header(forwarded_for: str, proxy_depth: int) -> str | None:
    if not forwarded_for:
        return None

    candidate = _forwarded_header_candidate(forwarded_for, proxy_depth)
    if candidate is None:
        return None

    addr = _forwarded_header_candidate_addr(candidate)
    if addr is None:
        return None

    if _forwarded_header_candidate_has_metachar(candidate):
        return None

    return _canonical_ip_text(addr)


def _is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


_forwarded_header_preemption_warned = False


def _warn_forwarded_header_preempted(
    connecting_ip: str, forwarded_for: str | None
) -> None:
    global _forwarded_header_preemption_warned
    if _forwarded_header_preemption_warned or not forwarded_for:
        return

    entries = [ip.strip() for ip in forwarded_for.split(",")]
    if connecting_ip not in entries:
        return

    _forwarded_header_preemption_warned = True
    logger.warning(
        "The connecting IP (%s) already appears inside its own "
        "X-Forwarded-For chain: the application server resolved the client "
        "from that header before guard-core ran, most likely because the "
        "server's own forwarded-header handling is enabled (uvicorn "
        "defaults to proxy_headers=True). While it is, the address "
        "guard-core sees is whatever the client claimed, so a rotating "
        "X-Forwarded-For defeats rate limiting and IP banning. To make "
        "guard-core the single authority, disable the server's handling "
        "(`uvicorn --no-proxy-headers`, or `proxy_headers=False` in "
        "uvicorn.run; gunicorn/hypercorn/WSGI servers have equivalent "
        "settings) AND declare the proxy via trusted_proxies / "
        "trusted_proxy_depth so guard-core resolves the real client itself. "
        "Disabling proxy_headers alone is not enough: if you also use "
        "enforce_https, set trust_x_forwarded_proto=True with the same "
        "trusted_proxies, otherwise the server stops forwarding the URL "
        "scheme and HTTPS detection breaks (infinite redirect loop) on "
        "TLS-terminating hosts such as Render or Heroku. This warning is "
        "logged once.",
        _sanitize_for_log(connecting_ip),
    )


async def _handle_untrusted_proxy(
    request: GuardRequest,
    connecting_ip: str,
    canonical_connecting_ip: str,
    forwarded_for: str | None,
    agent_handler: AgentHandlerProtocol | None,
) -> str:
    if forwarded_for:
        _warn_forwarded_header_preempted(connecting_ip, forwarded_for)
        safe_forwarded_for = _sanitize_for_log(forwarded_for)
        log_fn = (
            logger.debug if _is_private_or_loopback(connecting_ip) else logger.warning
        )
        log_fn(
            f"Potential IP spoof attempt: X-Forwarded-For header "
            f"({safe_forwarded_for}) received from untrusted IP "
            f"{_sanitize_for_log(connecting_ip)}"
        )
        await send_agent_event(
            agent_handler,
            "suspicious_request",
            canonical_connecting_ip,
            "spoofing_detected",
            f"Potential IP spoof attempt: X-Forwarded-For header {forwarded_for}",
            request,
        )
    return canonical_connecting_ip


_forwarded_header_chain_too_short_warned = False


def _warn_forwarded_header_chain_too_short(
    forwarded_for: str, proxy_depth: int, chain_length: int
) -> None:
    global _forwarded_header_chain_too_short_warned
    if _forwarded_header_chain_too_short_warned:
        return
    _forwarded_header_chain_too_short_warned = True
    logger.warning(
        "trusted_proxy_depth is %d but the X-Forwarded-For chain has only "
        "%d entries (%s); falling back to the connecting peer as the "
        "client. This warning is logged once.",
        proxy_depth,
        chain_length,
        _sanitize_for_log(forwarded_for),
    )


_forwarded_header_selected_entry_trusted_proxy_warned = False


def _warn_forwarded_header_selected_entry_trusted_proxy(entry: str) -> None:
    global _forwarded_header_selected_entry_trusted_proxy_warned
    if _forwarded_header_selected_entry_trusted_proxy_warned:
        return
    _forwarded_header_selected_entry_trusted_proxy_warned = True
    logger.warning(
        "trusted_proxy_depth selected %s from the X-Forwarded-For chain, "
        "but that address is itself listed in trusted_proxies; the chain "
        "likely has more proxy hops than trusted_proxy_depth accounts for. "
        "This warning is logged once.",
        _sanitize_for_log(entry),
    )


def _resolve_trusted_proxy_client_ip(
    canonical_connecting_ip: str,
    forwarded_for: str | None,
    proxy_depth: int,
    trusted_proxies: list[str],
) -> str:
    try:
        if not forwarded_for:
            return canonical_connecting_ip

        client_ip = _extract_from_forwarded_header(forwarded_for, proxy_depth)
        if client_ip:
            if _is_trusted_proxy(client_ip, trusted_proxies):
                _warn_forwarded_header_selected_entry_trusted_proxy(client_ip)
            return client_ip

        chain_length = len(forwarded_for.split(","))
        if chain_length < proxy_depth:
            _warn_forwarded_header_chain_too_short(
                forwarded_for, proxy_depth, chain_length
            )
    except (ValueError, IndexError) as e:
        logger.warning(f"Error processing client IP: {str(e)}")

    return canonical_connecting_ip


async def extract_client_ip(
    request: GuardRequest,
    config: Any,
    agent_handler: AgentHandlerProtocol | None = None,
) -> str:
    cached_ip: str | None = getattr(request.state, "client_ip", None)
    if cached_ip:
        return cached_ip

    if not request.client_host:
        if "unix" in config.trusted_proxies:
            forwarded_for = request.headers.get("X-Forwarded-For")
            return _resolve_trusted_proxy_client_ip(
                "unknown",
                forwarded_for,
                config.trusted_proxy_depth,
                config.trusted_proxies,
            )
        return "unknown"

    connecting_ip = request.client_host
    canonical_connecting_ip = _canonicalize_ip(connecting_ip)
    forwarded_for = request.headers.get("X-Forwarded-For")

    if not config.trusted_proxies:
        _warn_forwarded_header_preempted(connecting_ip, forwarded_for)
        return canonical_connecting_ip

    is_trusted = _is_trusted_proxy(connecting_ip, config.trusted_proxies)

    if not is_trusted:
        return await _handle_untrusted_proxy(
            request,
            connecting_ip,
            canonical_connecting_ip,
            forwarded_for,
            agent_handler,
        )

    return _resolve_trusted_proxy_client_ip(
        canonical_connecting_ip,
        forwarded_for,
        config.trusted_proxy_depth,
        config.trusted_proxies,
    )
