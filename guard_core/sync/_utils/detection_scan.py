import logging
from typing import Any

from guard_core.sync._utils.logging_utils import _log_at_level, _sanitize_for_reporting

logger = logging.getLogger("guard_core")


def _check_json_fields(
    data: dict,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
) -> tuple[bool, str]:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    for k, v in data.items():
        name_detected, name_trigger, _name_threats = _scan_component_name(
            k,
            f"{context}:{k}",
            f"JSON field name '{k}'",
            enabled_categories,
            client_ip,
            correlation_id,
            None,
        )
        if name_detected:
            return True, f"JSON field name '{k}': {name_trigger}"
        if isinstance(v, str):
            result = sus_patterns_handler.detect(
                content=v,
                ip_address=client_ip,
                context=f"{context}:{k}",
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


def _try_check_json_value(
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
            return _check_json_fields(
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


def _fallback_pattern_check(value: str) -> tuple[bool, str]:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    all_compiled = sus_patterns_handler.get_all_compiled_patterns()
    for pattern, _contexts, _category in all_compiled:
        try:
            if pattern.search(value):
                return True, "Value matched pattern (fallback)"
        except RecursionError:
            logger.warning(
                "Fallback pattern search hit the regex engine's recursion "
                "limit on pattern %r; skipping it and continuing the "
                "fallback scan",
                pattern.pattern,
            )
            continue
    return False, ""


def _check_value_enhanced(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
    scan_embedded_json: bool = True,
) -> tuple[bool, str, list[dict]]:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    if scan_embedded_json and context != "request_body":
        json_result = _try_check_json_value(
            value, context, client_ip, correlation_id, enabled_categories
        )
        if json_result is not None:
            detected, trigger = json_result
            if detected:
                return detected, trigger, []

    try:
        result = sus_patterns_handler.detect(
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
        detected, trigger = _fallback_pattern_check(value)
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


def _check_request_component(
    value: str,
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    log_level: str | None,
    scan_embedded_json: bool = True,
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats = _check_value_enhanced(
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


def _scan_component_name(
    name: str,
    context: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
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
            return True, f"Value matched pattern '{pattern.pattern}'", [threat]
    return False, "", []
