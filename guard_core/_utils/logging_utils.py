import json
import logging
from typing import Any

from guard_core._utils.pair_value_scan import _bounded_percent_decode

logger = logging.getLogger("guard_core")

_JSON_LEAF_START_CHARS = frozenset("{[")


def _sanitize_for_log(value: str) -> str:
    if not value:
        return value
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    sanitized = "".join(
        char if ord(char) >= 32 or char in "\t\n\r" else f"\\x{ord(char):02x}"
        for char in sanitized
    )
    return sanitized


def _sanitize_for_reporting(value: str) -> str:
    return value.encode("utf-8", errors="surrogateescape").decode(
        "utf-8", errors="backslashreplace"
    )


def _nested_json_leaf_candidate(value: str) -> str | None:
    if value[:1] in _JSON_LEAF_START_CHARS:
        return value
    if value[:1] != "%":
        return None
    decoded = _bounded_percent_decode(value)
    return decoded if decoded[:1] in _JSON_LEAF_START_CHARS else None


def _try_redact_nested_json_leaf(
    value: str,
    leaf_sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str | None:
    candidate = _nested_json_leaf_candidate(value)
    if candidate is None:
        return None
    try:
        parsed = json.loads(candidate)
    except ValueError:
        return None
    redacted = _redact_sensitive_json(
        parsed, leaf_sensitive, sensitive_body_fields, max_depth
    )
    if redacted == parsed:
        return None
    return json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)


def _redact_json_string_leaf(
    value: str,
    leaf_sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    from guard_core._utils.pair_redaction import _redact_pairs_in_text
    from guard_core._utils.request_logging import _redact_xml_elements

    nested_json = _try_redact_nested_json_leaf(
        value, leaf_sensitive, sensitive_body_fields, max_depth
    )
    if nested_json is not None:
        return nested_json

    xml_redacted = _redact_xml_elements(value, leaf_sensitive)
    return _redact_pairs_in_text(
        xml_redacted, leaf_sensitive, sensitive_body_fields, max_depth
    )


def _redact_json_child(
    key: Any,
    item: Any,
    source_is_dict: bool,
    depth: int,
    max_depth: int,
    leaf_sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    stack: list[tuple[Any, Any, int]],
) -> Any:
    if source_is_dict and str(key).lower() in sensitive_body_fields:
        return "[REDACTED]"
    if isinstance(item, str):
        return _redact_json_string_leaf(
            item, leaf_sensitive, sensitive_body_fields, max_depth
        )
    if not isinstance(item, dict | list):
        return item
    child_depth = depth + 1
    if child_depth >= max_depth:
        return "[REDACTED]"
    child: Any = {} if isinstance(item, dict) else []
    stack.append((item, child, child_depth))
    return child


def _redact_sensitive_json(
    value: Any,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> Any:
    if not isinstance(value, dict | list):
        return value
    if max_depth <= 1:
        return "[REDACTED]"
    leaf_sensitive = sensitive | sensitive_body_fields
    root: Any = {} if isinstance(value, dict) else []
    stack: list[tuple[Any, Any, int]] = [(value, root, 1)]
    while stack:
        source, target, depth = stack.pop()
        source_is_dict = isinstance(source, dict)
        entries = source.items() if source_is_dict else enumerate(source)
        for key, item in entries:
            redacted_item = _redact_json_child(
                key,
                item,
                source_is_dict,
                depth,
                max_depth,
                leaf_sensitive,
                sensitive_body_fields,
                stack,
            )
            if isinstance(target, dict):
                target[key] = redacted_item
            else:
                target.append(redacted_item)
    return root


def _log_at_level(logger: logging.Logger, level: str, msg: str) -> None:
    msg = _sanitize_for_reporting(msg)
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


class _YieldToHostRootHandlers(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not logging.getLogger().handlers


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
    console_handler.addFilter(_YieldToHostRootHandlers())
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
