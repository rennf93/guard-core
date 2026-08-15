import asyncio
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from guard_core.detection_result import DetectionResult
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.models import SecurityConfig


logger = logging.getLogger("guard_core")


def invoke_error_hook(
    hook: Callable[[str, BaseException, dict[str, Any]], None] | None,
    stage: str,
    exc: BaseException,
    context: dict[str, Any],
) -> None:
    if hook is None:
        return
    try:
        hook(stage, exc, context)
    except Exception as hook_error:
        logger.error(f"on_error hook raised while handling '{stage}': {hook_error}")


def _sanitize_for_log(value: str) -> str:
    if not value:
        return value
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    sanitized = "".join(
        char if ord(char) >= 32 or char in "\t\n\r" else f"\\x{ord(char):02x}"
        for char in sanitized
    )
    return sanitized


def get_pipeline_response_time(request: GuardRequest | None) -> float | None:
    if request is None:
        return None
    pipeline_start = getattr(request.state, "_guard_pipeline_start", None)
    if not isinstance(pipeline_start, int | float):
        pipeline_start = time.monotonic()
        request.state._guard_pipeline_start = pipeline_start
    return time.monotonic() - pipeline_start


async def send_agent_event(
    agent_handler: AgentHandlerProtocol | None,
    event_type: str,
    ip_address: str,
    action_taken: str,
    reason: str,
    request: GuardRequest | None = None,
    **kwargs: Any,
) -> None:
    if not agent_handler:
        return

    try:
        endpoint = None
        method = None
        user_agent = None
        country = None

        if request:
            endpoint = request.url_path
            method = request.method
            user_agent = request.headers.get("User-Agent")

        from guard_core._pydantic_plugin_mute import get_telemetry_model

        SecurityEvent = get_telemetry_model("SecurityEvent")

        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            ip_address=ip_address,
            country=country,
            user_agent=user_agent,
            action_taken=action_taken,
            reason=reason,
            endpoint=endpoint,
            method=method,
            response_time=get_pipeline_response_time(request),
            **kwargs,
        )

        await agent_handler.send_event(event)
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to send agent event: {e}")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json

        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_entry, default=str)


def _create_formatter(log_format: str) -> logging.Formatter:
    if log_format == "json":
        return JsonFormatter()
    return logging.Formatter("[%(name)s] %(asctime)s - %(levelname)s - %(message)s")


def setup_custom_logging(
    log_file: str | None = None, log_format: str = "text"
) -> logging.Logger:
    logger = logging.getLogger("guard_core")
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    formatter = _create_formatter(log_format)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        try:
            import os

            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to create log file {log_file}: {e}")

    logger.setLevel(logging.INFO)

    return logger


def _is_trusted_proxy(connecting_ip: str, trusted_proxies: list[str]) -> bool:
    try:
        connecting_ip_obj = ip_address(connecting_ip)

        for proxy in trusted_proxies:
            if "/" in proxy:
                if connecting_ip_obj in ip_network(proxy, strict=False):
                    return True
            elif connecting_ip == proxy:
                return True
        return False
    except ValueError:
        return False


def _extract_from_forwarded_header(forwarded_for: str, proxy_depth: int) -> str | None:
    if not forwarded_for:
        return None

    ips = [ip.strip() for ip in forwarded_for.split(",")]

    if len(ips) >= proxy_depth:
        return ips[-proxy_depth]

    return None


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


async def extract_client_ip(
    request: GuardRequest,
    config: Any,
    agent_handler: AgentHandlerProtocol | None = None,
) -> str:
    cached_ip: str | None = getattr(request.state, "client_ip", None)
    if cached_ip:
        return cached_ip

    if not request.client_host:
        return "unknown"

    connecting_ip = request.client_host
    forwarded_for = request.headers.get("X-Forwarded-For")

    if not config.trusted_proxies:
        _warn_forwarded_header_preempted(connecting_ip, forwarded_for)
        return connecting_ip

    is_trusted = _is_trusted_proxy(connecting_ip, config.trusted_proxies)

    if not is_trusted:
        if forwarded_for:
            _warn_forwarded_header_preempted(connecting_ip, forwarded_for)
            safe_forwarded_for = _sanitize_for_log(forwarded_for)
            log_fn = (
                logger.debug
                if _is_private_or_loopback(connecting_ip)
                else logger.warning
            )
            log_fn(
                f"Potential IP spoof attempt: X-Forwarded-For header "  # nosemgrep
                f"({safe_forwarded_for}) received from untrusted IP {connecting_ip}"
            )
            await send_agent_event(
                agent_handler,
                "suspicious_request",
                connecting_ip,
                "spoofing_detected",
                f"Potential IP spoof attempt: X-Forwarded-For header {forwarded_for}",
                request,
            )
        return connecting_ip

    try:
        if not forwarded_for:
            return connecting_ip

        client_ip = _extract_from_forwarded_header(
            forwarded_for, config.trusted_proxy_depth
        )
        if client_ip:
            return client_ip
    except (ValueError, IndexError) as e:
        logger.warning(f"Error processing client IP: {str(e)}")

    return connecting_ip


def _extract_request_context(request: GuardRequest) -> dict[str, Any]:
    client_ip = "unknown"
    if request.client_host:
        client_ip = request.client_host

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


def _log_at_level(logger: logging.Logger, level: str, msg: str) -> None:
    if level == "INFO":
        logger.info(msg)
    elif level == "DEBUG":
        logger.debug(msg)
    elif level == "WARNING":
        logger.warning(msg)
    elif level == "ERROR":
        logger.error(msg)
    elif level == "CRITICAL":
        logger.critical(msg)


async def log_activity(
    request: GuardRequest,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING",
    check_name: str | None = None,
    muted_check_logs: frozenset[str] | None = None,
) -> None:
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


async def is_user_agent_allowed(user_agent: str, config: Any) -> bool:
    for pattern in config.blocked_user_agents:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return False
    return True


def _extract_ip_from_request(request: str | GuardRequest) -> str:
    if isinstance(request, str):
        return request
    return request.client_host if request.client_host else "unknown"


def _has_country_rules(config: Any) -> bool:
    return bool(config.blocked_countries or config.whitelist_countries)


def _log_country_check_result(
    ip: str, country: str | None, result_type: str, config: Any
) -> None:
    if result_type == "no_rules":
        logger.debug(
            f"No countries blocked or whitelisted {ip} - "
            "No countries blocked or whitelisted"
        )
    elif result_type == "no_geolocation":
        logger.debug(f"IP not geolocated {ip} - IP geolocation failed")
    elif result_type == "blocked":
        level = config.log_suspicious_level
        if level is None:
            return
        _log_at_level(
            logger,
            level,
            f"IP from blocked country {ip} - {country} - IP from blocked country",
        )
    elif result_type in ("whitelisted", "not_affected"):
        level = config.log_country_check_level
        if level is None:
            return
        if result_type == "whitelisted":
            _log_at_level(
                logger,
                level,
                f"IP from whitelisted country {ip} - {country} - "
                "IP from whitelisted country",
            )
        else:
            _log_at_level(
                logger,
                level,
                f"IP not from blocked or whitelisted country {ip} - {country} - "
                "IP not from blocked or whitelisted country",
            )


def _evaluate_country_access(country: str, config: Any) -> tuple[bool, str]:
    if config.whitelist_countries:
        if country in config.whitelist_countries:
            return False, "whitelisted"
        return True, "blocked"

    if config.blocked_countries and country in config.blocked_countries:
        return True, "blocked"

    return False, "not_affected"


async def _resolve_country_verdict(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler
) -> tuple[bool, str | None]:
    if not _has_country_rules(config):
        _log_country_check_result(ip, None, "no_rules", config)
        return False, None

    if not geo_ip_handler.is_initialized:
        await geo_ip_handler.initialize()

    country = geo_ip_handler.get_country(ip)

    if not country:
        _log_country_check_result(ip, None, "no_geolocation", config)
        return bool(config.whitelist_countries), None

    is_blocked, result_type = _evaluate_country_access(country, config)
    _log_country_check_result(ip, country, result_type, config)

    return is_blocked, country


async def check_ip_country(
    request: str | GuardRequest,
    config: Any,
    geo_ip_handler: GeoIPHandler,
) -> bool:
    ip = _extract_ip_from_request(request)
    is_blocked, _country = await _resolve_country_verdict(ip, config, geo_ip_handler)
    return is_blocked


def _ip_in_list(ip_addr: Any, ip: str, entries: list[str] | None) -> bool:
    if not entries:
        return False
    for entry in entries:
        if "/" in entry:
            if ip_addr in ip_network(entry, strict=False):
                return True
        else:
            try:
                if ip_addr == ip_address(entry):
                    return True
            except ValueError:
                if ip == entry:
                    return True
    return False


async def _check_blacklist(ip_addr: Any, ip: str, config: Any) -> bool:
    return not _ip_in_list(ip_addr, ip, config.blacklist)


async def _check_whitelist(ip_addr: Any, ip: str, config: Any) -> bool:
    if config.whitelist:
        return _ip_in_list(ip_addr, ip, config.whitelist)
    return True


async def _check_blocked_countries(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler | None
) -> bool:
    if (config.blocked_countries or config.whitelist_countries) and geo_ip_handler:
        country_blocked = await check_ip_country(ip, config, geo_ip_handler)
        if country_blocked:
            return False
    return True


@dataclass(frozen=True)
class IpAccessResult:
    allowed: bool
    reason: str
    cloud_provider: str | None = None
    network: str | None = None


_GENERIC_LIST_BLOCK_REASON = "IP {ip} not in global allowlist/blocklist"


async def _check_blocked_countries_detail(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler | None
) -> IpAccessResult | None:
    if (
        not (config.blocked_countries or config.whitelist_countries)
        or not geo_ip_handler
    ):
        return None

    is_blocked, country = await _resolve_country_verdict(ip, config, geo_ip_handler)
    if not is_blocked:
        return None

    reason = (
        f"IP from blocked country: {country}"
        if country
        else _GENERIC_LIST_BLOCK_REASON.format(ip=ip)
    )
    return IpAccessResult(False, reason)


async def _check_cloud_providers_detail(ip: str, config: Any) -> IpAccessResult | None:
    from guard_core.handlers.cloud_handler import cloud_handler

    if not config.block_cloud_providers:
        return None
    if not cloud_handler.is_cloud_ip(ip, config.block_cloud_providers):
        return None

    details = cloud_handler.get_cloud_provider_details(ip, config.block_cloud_providers)
    if details is None:
        return IpAccessResult(False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip))

    provider, network = details
    return IpAccessResult(
        False,
        f"IP belongs to blocked cloud provider: {provider}",
        cloud_provider=provider,
        network=network,
    )


async def check_ip_access(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
    *,
    skip_ip_lists: bool = False,
    skip_countries: bool = False,
) -> IpAccessResult:
    try:
        ip_addr = ip_address(ip)

        if not skip_ip_lists:
            if config.whitelist:
                if not await _check_whitelist(ip_addr, ip, config):
                    return IpAccessResult(
                        False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip)
                    )
            elif not await _check_blacklist(ip_addr, ip, config):
                return IpAccessResult(False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip))

        if not skip_countries:
            country_result = await _check_blocked_countries_detail(
                ip, config, geo_ip_handler
            )
            if country_result is not None:
                return country_result

        cloud_result = await _check_cloud_providers_detail(ip, config)
        if cloud_result is not None:
            return cloud_result

        return IpAccessResult(True, "")
    except ValueError:
        return IpAccessResult(False, _GENERIC_LIST_BLOCK_REASON.format(ip=ip))
    except Exception as e:
        logger.error(f"Error checking IP {ip}: {str(e)}")
        return IpAccessResult(True, "")


async def is_ip_allowed(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
    *,
    skip_ip_lists: bool = False,
    skip_countries: bool = False,
) -> bool:
    result = await check_ip_access(
        ip,
        config,
        geo_ip_handler,
        skip_ip_lists=skip_ip_lists,
        skip_countries=skip_countries,
    )
    return result.allowed


async def _check_json_fields(
    data: dict,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
) -> tuple[bool, str]:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    for k, v in data.items():
        name_detected, name_trigger, _name_threats = await _scan_component_name(
            k,
            f"{context}.{k}",
            f"JSON field name '{k}'",
            enabled_categories,
            client_ip,
            correlation_id,
            None,
        )
        if name_detected:
            return True, f"JSON field name '{k}': {name_trigger}"
        if isinstance(v, str):
            result = await sus_patterns_handler.detect(
                content=v,
                ip_address=client_ip,
                context=f"{context}.{k}",
                correlation_id=correlation_id,
            )
            if result["is_threat"]:
                if result["threats"]:
                    threat = result["threats"][0]
                    if threat["type"] == "regex":
                        pattern = threat["pattern"]
                        return True, f"JSON field '{k}' matched pattern '{pattern}'"
                    else:
                        threat_type = threat["type"]
                        return True, f"JSON field '{k}' contains: {threat_type}"
                return True, f"JSON field '{k}' contains threat"
    return False, ""


async def _try_check_json_value(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
) -> tuple[bool, str] | None:
    try:
        import json

        data = json.loads(value)
        if isinstance(data, dict):
            return await _check_json_fields(
                data, context, client_ip, correlation_id, enabled_categories
            )
    except json.JSONDecodeError:
        pass
    return None


def _build_threat_message(threat: dict[str, Any]) -> str:
    if threat["type"] == "regex":
        return f"Value matched pattern '{threat['pattern']}'"
    elif threat["type"] == "semantic":
        attack_type = threat.get("attack_type", "suspicious")
        score = threat.get("probability", threat.get("threat_score", 0))
        return f"Semantic attack: {attack_type} (score: {score:.2f})"
    return "Threat detected"


async def _fallback_pattern_check(value: str) -> tuple[bool, str]:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    all_compiled = await sus_patterns_handler.get_all_compiled_patterns()
    for pattern, _contexts, _category in all_compiled:
        try:
            if pattern.search(value):
                return True, "Value matched pattern (fallback)"
        except Exception:
            continue
    return False, ""


async def _check_value_enhanced(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
    scan_embedded_json: bool = True,
) -> tuple[bool, str, list[dict]]:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    if scan_embedded_json and context != "request_body":
        json_result = await _try_check_json_value(
            value, context, client_ip, correlation_id, enabled_categories
        )
        if json_result is not None:
            detected, trigger = json_result
            return detected, trigger, []

    try:
        result = await sus_patterns_handler.detect(
            content=value,
            ip_address=client_ip,
            context=context,
            correlation_id=correlation_id,
            enabled_categories=enabled_categories,
        )

        if not result["is_threat"]:
            return False, "", []

        threats: list[dict] = list(result.get("threats", []))
        if threats:
            return True, _build_threat_message(threats[0]), threats

        return True, "Threat detected", threats

    except Exception as e:
        logger.error(f"Enhanced detection failed: {e}, falling back to basic check")
        detected, trigger = await _fallback_pattern_check(value)
        return detected, trigger, []


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


async def _check_request_component(
    value: str,
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    log_level: str | None,
    scan_embedded_json: bool = True,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = await _check_value_enhanced(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        scan_embedded_json,
    )
    if detected:
        _log_detected_component(value, component_name, client_ip, log_level)
    return detected, trigger, threats


async def _scan_component_name(
    name: str,
    context: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    return await _check_request_component(
        name,
        context,
        label,
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        scan_embedded_json=False,
    )


def _check_always_scan_header(value: str) -> tuple[bool, str, list[dict]]:
    from guard_core.handlers.suspatterns_handler import ALWAYS_SCAN_HEADER_PATTERNS

    for pattern in ALWAYS_SCAN_HEADER_PATTERNS:
        match = pattern.search(value)
        if match:
            threat = {
                "type": "regex",
                "pattern": pattern.pattern,
                "match": match.group(),
                "position": match.start(),
                "category": "cmd_injection",
            }
            return True, f"Value matched pattern '{pattern.pattern}'", [threat]
    return False, "", []


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


async def _scan_query_params(
    request: GuardRequest,
    excluded_params: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
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
        detected, trigger, threats = await _check_request_component(
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


async def _scan_headers(
    request: GuardRequest,
    excluded_headers: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    for key, value in request.headers.items():
        if key.lower() in excluded_headers:
            if (
                enabled_categories is not None
                and "cmd_injection" not in enabled_categories
            ):
                continue
            detected, trigger, threats = _check_always_scan_header(key)
            if detected:
                _log_detected_component(
                    key, f"header name '{key}'", client_ip, log_level
                )
                return True, f"Header name '{key}': {trigger}", threats
            detected, trigger, threats = _check_always_scan_header(value)
            if detected:
                _log_detected_component(value, f"header '{key}'", client_ip, log_level)
                return True, f"Header '{key}': {trigger}", threats
            continue
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
        )
        if detected:
            return True, f"Header '{key}': {trigger}", threats
    return False, "", []


async def _scan_body_field(
    value: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = await _check_request_component(
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


async def _scan_blob_body(
    raw_body: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = await _check_request_component(
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


async def _scan_json_value(
    value: Any,
    key_label: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    if isinstance(value, dict):
        for key, item in value.items():
            key_str = str(key)
            if key_str.lower() in excluded_body_fields:
                continue
            if _MONGO_OPERATOR_KEY_RE.match(key_str):
                threat = {
                    "type": "regex",
                    "pattern": _MONGO_OPERATOR_KEY_RE.pattern,
                    "match": key_str,
                    "position": 0,
                    "category": "nosql",
                }
                return (
                    True,
                    f"JSON operator key '{key_str}': matched pattern "
                    f"'{_MONGO_OPERATOR_KEY_RE.pattern}'",
                    [threat],
                )
            name_hit = await _scan_component_name(
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
            hit = await _scan_json_value(
                item,
                key_str,
                excluded_body_fields,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
            )
            if hit[0]:
                return hit
        return False, "", []
    if isinstance(value, list):
        for item in value:
            hit = await _scan_json_value(
                item,
                key_label,
                excluded_body_fields,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
            )
            if hit[0]:
                return hit
        return False, "", []
    return await _scan_body_field(
        str(value), key_label, enabled_categories, client_ip, correlation_id, log_level
    )


async def _scan_form_body(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    from urllib.parse import parse_qsl

    for name, value in parse_qsl(raw_body, keep_blank_values=True):
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
            value, name, enabled_categories, client_ip, correlation_id, log_level
        )
        if hit[0]:
            return hit
    return False, "", []


def _multipart_text_parts(
    raw_body: str, content_type: str
) -> list[tuple[str, str]] | None:
    from email.parser import Parser
    from email.policy import compat32

    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n"
    message = Parser(policy=compat32).parsestr(header + raw_body)
    if not message.is_multipart():
        return None
    parts: list[tuple[str, str]] = []
    for part in message.walk():
        if part.is_multipart() or part.get_filename():
            continue
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=False)
        if name is None or not isinstance(payload, str):
            continue
        parts.append((str(name), payload))
    return parts


async def _scan_multipart_body(
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
        return await _scan_blob_body(
            raw_body, enabled_categories, client_ip, correlation_id, log_level
        )
    for name, value in parts:
        if name.lower() in excluded_body_fields:
            continue
        name_hit = await _scan_component_name(
            name,
            "request_body",
            f"multipart field name '{name}'",
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
        )
        if name_hit[0]:
            return True, f"Multipart field name '{name}': {name_hit[1]}", name_hit[2]
        hit = await _scan_body_field(
            value, name, enabled_categories, client_ip, correlation_id, log_level
        )
        if hit[0]:
            return hit
    return False, "", []


async def _scan_request_body(
    raw_body: str,
    content_type: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
) -> tuple[bool, str, list[dict]]:
    import json

    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        return await _scan_form_body(
            raw_body,
            excluded_body_fields,
            enabled_categories,
            client_ip,
            correlation_id,
            log_level,
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
        )

    if "json" in lowered:
        try:
            parsed_body = json.loads(raw_body)
        except Exception:
            parsed_body = None
        if isinstance(parsed_body, dict | list):
            return await _scan_json_value(
                parsed_body,
                "",
                excluded_body_fields,
                enabled_categories,
                client_ip,
                correlation_id,
                log_level,
            )
    return await _scan_blob_body(
        raw_body, enabled_categories, client_ip, correlation_id, log_level
    )


def _threat_category(threat: dict) -> str | None:
    if threat.get("type") == "regex":
        category = threat.get("category")
        return category if isinstance(category, str) else None
    if threat.get("type") == "semantic":
        attack_type = threat.get("attack_type")
        return attack_type if isinstance(attack_type, str) else None
    return None


def _threat_score(threat: dict) -> float:
    if "probability" in threat:
        return float(threat["probability"])
    if "threat_score" in threat:
        return float(threat["threat_score"])
    return 1.0


def _build_detection_hit(trigger: str, threats: list[dict]) -> DetectionResult:
    categories: list[str] = []
    scores: dict[str, float] = {}
    for threat in threats:
        category = _threat_category(threat)
        if category is None:
            continue
        if category not in categories:
            categories.append(category)
        score = _threat_score(threat)
        scores[category] = max(scores.get(category, 0.0), score)
    return DetectionResult(
        is_threat=True,
        trigger_info=trigger,
        threat_categories=categories,
        threat_scores=scores,
    )


def _build_detection_miss() -> DetectionResult:
    return DetectionResult(is_threat=False, trigger_info="")


_CONTENT_LENGTH_RE = re.compile(r"[0-9]+")


def _parse_content_length(value: str) -> int | None:
    stripped = value.strip()
    if not _CONTENT_LENGTH_RE.fullmatch(stripped):
        return None
    parsed = int(stripped)
    return parsed if parsed > 0 else None


@runtime_checkable
class _BoundedBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...


_DEFAULT_BODY_READ_TIMEOUT = 3.0
_DEFAULT_BODY_READ_MAX_CONCURRENT = 64
_MAX_STRADDLE_OVERLAP_BYTES = 256


async def _safe_read(
    reader: Callable[[], Awaitable[bytes]],
    timeout: float,
    max_concurrent: int = _DEFAULT_BODY_READ_MAX_CONCURRENT,
) -> bytes | None:
    try:
        return await asyncio.wait_for(reader(), timeout=timeout)
    except Exception:
        return None


async def _straddle_overlap_bytes() -> int:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    try:
        patterns = await sus_patterns_handler.get_all_compiled_patterns()
    except Exception:
        return 0

    if not patterns:
        return 0

    longest = max(len(pattern.pattern) for pattern, _contexts, _category in patterns)
    return min(longest, _MAX_STRADDLE_OVERLAP_BYTES)


_CAPPED_BODY_PREFIX_STATE_ATTR = "_guard_capped_body_prefix_cache"


async def _read_and_cache_body(
    request: GuardRequest,
    max_bytes: int,
    timeout: float,
    reader: Callable[[], Awaitable[bytes]],
    accessor: str,
    max_concurrent: int,
) -> bytes | None:
    cached = getattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, None)
    if cached is not None and cached[0] is request and cached[1] >= max_bytes:
        cached_bytes: bytes = cached[2]
        return cached_bytes[:max_bytes]

    prefix: object = await _safe_read(reader, timeout, max_concurrent)
    if prefix is None:
        return None

    if not isinstance(prefix, bytes):
        logger.warning(
            "%s.%s returned %s, not bytes; treating the "
            "body as unavailable for detection",
            type(request).__name__,
            accessor,
            type(prefix).__name__,
        )
        return None

    capped = prefix[:max_bytes]
    setattr(request.state, _CAPPED_BODY_PREFIX_STATE_ATTR, (request, max_bytes, capped))
    return capped


async def _read_capped_body_prefix(
    request: GuardRequest, max_bytes: int, timeout: float, max_concurrent: int
) -> bytes | None:
    if not isinstance(request, _BoundedBodyReader):
        return None

    fetch_bytes = max_bytes + await _straddle_overlap_bytes()
    return await _read_and_cache_body(
        request,
        fetch_bytes,
        timeout,
        lambda: request.read_body_prefix(fetch_bytes),
        "read_body_prefix",
        max_concurrent,
    )


async def _read_capped_body(
    request: GuardRequest, config: "SecurityConfig | None"
) -> bytes | None:
    if config is None:
        return await _safe_read(
            request.body, _DEFAULT_BODY_READ_TIMEOUT, _DEFAULT_BODY_READ_MAX_CONCURRENT
        )

    max_bytes = config.detection_max_body_inspect_bytes
    timeout = config.body_read_timeout
    max_concurrent = config.sync_body_read_max_concurrent
    content_length = request.headers.get("content-length")

    if content_length is not None:
        parsed = _parse_content_length(content_length)
        if parsed is not None and parsed > max_bytes:
            return None
        if parsed is not None:
            return await _read_and_cache_body(
                request, max_bytes, timeout, request.body, "body", max_concurrent
            )

    return await _read_capped_body_prefix(request, max_bytes, timeout, max_concurrent)


def _resolve_log_level(config: "SecurityConfig | None") -> str | None:
    return config.log_suspicious_level if config is not None else "WARNING"


async def detect_penetration_attempt(
    request: GuardRequest,
    config: "SecurityConfig | None" = None,
    route_config: "RouteConfig | None" = None,
) -> DetectionResult:
    import uuid

    client_ip = request.client_host or "unknown"
    correlation_id = str(uuid.uuid4())

    excluded_params = _resolve_excluded_params(config, route_config)
    excluded_body_fields = _resolve_excluded_body_fields(config, route_config)
    enabled_categories = _resolve_enabled_categories(config, route_config)
    excluded_headers = _resolve_excluded_headers(config, route_config)
    log_level = _resolve_log_level(config)

    detected, trigger, threats = await _scan_query_params(
        request,
        excluded_params,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    detected, trigger, threats = await _check_request_component(
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

    detected, trigger, threats = await _scan_headers(
        request,
        excluded_headers,
        enabled_categories,
        client_ip,
        correlation_id,
        log_level,
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    if not _resolve_scan_body(config, route_config):
        return _build_detection_miss()

    body_bytes = await _read_capped_body(request, config)
    if body_bytes is None:
        return _build_detection_miss()

    try:
        raw_body = body_bytes.decode()
    except Exception:
        return _build_detection_miss()

    content_type = request.headers.get("content-type") or ""
    detected, trigger, threats = await _scan_request_body(
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
