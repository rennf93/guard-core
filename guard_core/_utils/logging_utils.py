import logging
from typing import Any

logger = logging.getLogger("guard_core")


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


def _redact_sensitive_json(
    value: Any, sensitive_body_fields: frozenset[str], max_depth: int
) -> Any:
    if not isinstance(value, dict | list):
        return value
    if max_depth <= 1:
        return "[REDACTED]"
    root: Any = {} if isinstance(value, dict) else []
    stack: list[tuple[Any, Any, int]] = [(value, root, 1)]
    while stack:
        source, target, depth = stack.pop()
        entries = source.items() if isinstance(source, dict) else enumerate(source)
        for key, item in entries:
            if isinstance(source, dict) and str(key).lower() in sensitive_body_fields:
                redacted_item: Any = "[REDACTED]"
            elif isinstance(item, dict | list):
                child_depth = depth + 1
                if child_depth >= max_depth:
                    redacted_item = "[REDACTED]"
                else:
                    redacted_item = {} if isinstance(item, dict) else []
                    stack.append((item, redacted_item, child_depth))
            else:
                redacted_item = item
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
