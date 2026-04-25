import logging
import re
import time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any, Literal

from guard_core.detection_result import DetectionResult
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest

if TYPE_CHECKING:
    from guard_core.decorators.base import RouteConfig
    from guard_core.models import SecurityConfig


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
    if not isinstance(pipeline_start, (int, float)):
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

        from guard_agent import SecurityEvent

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
        client_ip_index = 0
        return ips[client_ip_index]

    return None


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
        return connecting_ip

    is_trusted = _is_trusted_proxy(connecting_ip, config.trusted_proxies)

    if not is_trusted:
        if forwarded_for:
            safe_forwarded_for = _sanitize_for_log(forwarded_for)
            logging.warning(
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
        logging.warning(f"Error processing client IP: {str(e)}")

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
    muted_check_logs: set[str] | None = None,
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


def _log_country_check_result(ip: str, country: str | None, result_type: str) -> None:
    if result_type == "no_rules":
        logging.warning(
            f"No countries blocked or whitelisted {ip} - "
            "No countries blocked or whitelisted"
        )
    elif result_type == "no_geolocation":
        logging.warning(f"IP not geolocated {ip} - IP geolocation failed")
    elif result_type == "whitelisted":
        logging.info(
            f"IP from whitelisted country {ip} - {country} - "
            "IP from whitelisted country"
        )
    elif result_type == "blocked":
        logging.warning(
            f"IP from blocked country {ip} - {country} - IP from blocked country"
        )
    elif result_type == "not_affected":
        logging.info(
            f"IP not from blocked or whitelisted country {ip} - {country} - "
            "IP not from blocked or whitelisted country"
        )


def _evaluate_country_access(country: str, config: Any) -> tuple[bool, str]:
    if config.whitelist_countries and country in config.whitelist_countries:
        return False, "whitelisted"

    if config.blocked_countries and country in config.blocked_countries:
        return True, "blocked"

    return False, "not_affected"


async def check_ip_country(
    request: str | GuardRequest,
    config: Any,
    geo_ip_handler: GeoIPHandler,
) -> bool:
    if not _has_country_rules(config):
        ip = _extract_ip_from_request(request)
        _log_country_check_result(ip, None, "no_rules")
        return False

    if not geo_ip_handler.is_initialized:
        await geo_ip_handler.initialize()

    ip = _extract_ip_from_request(request)
    country = geo_ip_handler.get_country(ip)

    if not country:
        _log_country_check_result(ip, None, "no_geolocation")
        return False

    is_blocked, result_type = _evaluate_country_access(country, config)
    _log_country_check_result(ip, country, result_type)

    return is_blocked


async def _check_blacklist(ip_addr: Any, ip: str, config: Any) -> bool:
    if config.blacklist:
        for blocked in config.blacklist:
            if "/" in blocked:
                if ip_addr in ip_network(blocked, strict=False):
                    return False
            elif ip == blocked:
                return False
    return True


async def _check_whitelist(ip_addr: Any, ip: str, config: Any) -> bool:
    if config.whitelist:
        for allowed in config.whitelist:
            if "/" in allowed:
                if ip_addr in ip_network(allowed, strict=False):
                    return True
            elif ip == allowed:
                return True
        return False
    return True


async def _check_blocked_countries(
    ip: str, config: Any, geo_ip_handler: GeoIPHandler | None
) -> bool:
    if config.blocked_countries and geo_ip_handler:
        country_blocked = await check_ip_country(ip, config, geo_ip_handler)
        if country_blocked:
            return False
    return True


async def _check_cloud_providers(ip: str, config: Any) -> bool:
    from guard_core.handlers.cloud_handler import cloud_handler

    if config.block_cloud_providers and cloud_handler.is_cloud_ip(
        ip, config.block_cloud_providers
    ):
        return False
    return True


async def is_ip_allowed(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
) -> bool:
    try:
        ip_addr = ip_address(ip)

        if not await _check_blacklist(ip_addr, ip, config):
            return False

        if not await _check_whitelist(ip_addr, ip, config):
            return False

        if not await _check_blocked_countries(ip, config, geo_ip_handler):
            return False

        if not await _check_cloud_providers(ip, config):
            return False

        return True
    except ValueError:
        return False
    except Exception as e:
        logging.error(f"Error checking IP {ip}: {str(e)}")
        return True


async def _check_json_fields(
    data: dict,
    context: str,
    client_ip: str,
    correlation_id: str,
) -> tuple[bool, str]:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    for k, v in data.items():
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
    value: str, context: str, client_ip: str, correlation_id: str
) -> tuple[bool, str] | None:
    try:
        import json

        data = json.loads(value)
        if isinstance(data, dict):
            return await _check_json_fields(data, context, client_ip, correlation_id)
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
) -> tuple[bool, str, list[dict]]:
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    json_result = await _try_check_json_value(value, context, client_ip, correlation_id)
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
        logging.error(f"Enhanced detection failed: {e}, falling back to basic check")
        detected, trigger = await _fallback_pattern_check(value)
        return detected, trigger, []


async def _check_request_component(
    value: str,
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = await _check_value_enhanced(
        value, context, client_ip, correlation_id, enabled_categories
    )
    if detected:
        message = "Potential attack detected from"
        details = (
            f"{client_ip}: {value[:100]}..."
            if len(value) > 100
            else f"{client_ip}: {value}"
        )
        reason_message = f"Suspicious pattern in {component_name}"
        logging.warning(f"{message} {details} - {reason_message}")
    return detected, trigger, threats


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
) -> tuple[bool, str, list[dict]]:
    for key, value in request.query_params.items():
        if key.lower() in excluded_params:
            continue
        detected, trigger, threats = await _check_request_component(
            value,
            f"query_param:{key}",
            f"query param '{key}'",
            client_ip,
            correlation_id,
            enabled_categories,
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
) -> tuple[bool, str, list[dict]]:
    for key, value in request.headers.items():
        if key.lower() in excluded_headers:
            continue
        detected, trigger, threats = await _check_request_component(
            value,
            f"header:{key}",
            f"header '{key}'",
            client_ip,
            correlation_id,
            enabled_categories,
        )
        if detected:
            return True, f"Header '{key}': {trigger}", threats
    return False, "", []


async def _scan_request_body(
    raw_body: str,
    excluded_body_fields: set[str],
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
) -> tuple[bool, str, list[dict]]:
    import json

    parsed_body: Any | None = None
    if excluded_body_fields:
        try:
            parsed_body = json.loads(raw_body)
        except Exception:
            parsed_body = None

    if isinstance(parsed_body, dict):
        for key, value in parsed_body.items():
            if str(key).lower() in excluded_body_fields:
                continue
            detected, trigger, threats = await _check_request_component(
                str(value),
                "request_body",
                f"request body field '{key}'",
                client_ip,
                correlation_id,
                enabled_categories,
            )
            if detected:
                return True, f"Request body field '{key}': {trigger}", threats
        return False, "", []

    detected, trigger, threats = await _check_request_component(
        raw_body,
        "request_body",
        "request body",
        client_ip,
        correlation_id,
        enabled_categories,
    )
    if detected:
        return True, f"Request body: {trigger}", threats
    return False, "", []


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


async def detect_penetration_attempt(
    request: GuardRequest,
    config: "SecurityConfig | None" = None,
    route_config: "RouteConfig | None" = None,
) -> DetectionResult:
    import uuid

    client_ip = "unknown"
    if request.client_host:
        client_ip = request.client_host

    correlation_id = str(uuid.uuid4())

    excluded_params = _resolve_excluded_params(config, route_config)
    excluded_body_fields = _resolve_excluded_body_fields(config, route_config)
    enabled_categories = _resolve_enabled_categories(config, route_config)
    excluded_headers = _resolve_excluded_headers(config, route_config)

    detected, trigger, threats = await _scan_query_params(
        request, excluded_params, enabled_categories, client_ip, correlation_id
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
    )
    if detected:
        return _build_detection_hit(f"URL path: {trigger}", threats)

    detected, trigger, threats = await _scan_headers(
        request, excluded_headers, enabled_categories, client_ip, correlation_id
    )
    if detected:
        return _build_detection_hit(trigger, threats)

    try:
        raw_body = (await request.body()).decode()
    except Exception:
        return _build_detection_miss()

    detected, trigger, threats = await _scan_request_body(
        raw_body, excluded_body_fields, enabled_categories, client_ip, correlation_id
    )
    if detected:
        return _build_detection_hit(trigger, threats)
    return _build_detection_miss()
