---

title: Logging Configuration
description: Configuring log levels, formats, file output, and the JsonFormatter in guard-core
keywords: logging, json formatter, log levels, security events, guard-core
---

Logging Configuration
=====================

Guard-core uses Python's standard `logging` module with configurable levels, formats, and output destinations.

Log Level Fields
----------------

### `log_suspicious_level`

**Type**: `"INFO" | "DEBUG" | "WARNING" | "ERROR" | "CRITICAL" | None`
**Default**: `"WARNING"`

Controls the log level for suspicious activity events (blocked requests, penetration attempts, banned IPs, rate limit violations).

Set to `None` to suppress suspicious activity logging entirely.

### `log_request_level`

**Type**: Same as above
**Default**: `None`

Controls the log level for all incoming requests (the `RequestLoggingCheck`). Disabled by default to avoid high-volume logging in production.

Set to `"INFO"` or `"DEBUG"` for development or audit requirements.

___

Log Format
----------

### `log_format`

**Type**: `"text" | "json"`
**Default**: `"text"`

**Text format** (default):

```text
[guard_core] 2026-03-23 10:15:32,123 - WARNING - Suspicious activity detected from 10.0.0.1: GET /api/data - Reason: SQL injection pattern matched - Headers: {...}
```

**JSON format**:

```json
{"timestamp": "2026-03-23 10:15:32,123", "level": "WARNING", "logger": "guard_core", "message": "Suspicious activity detected from 10.0.0.1: GET /api/data - Reason: SQL injection pattern matched - Headers: {...}"}
```

### JsonFormatter

The `JsonFormatter` class in `guard_core.utils` produces structured JSON log output:

```python
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_entry, default=str)
```

Adapters can use this formatter directly for custom logging handlers.

___

Custom Log File
---------------

### `custom_log_file`

**Type**: `str | None`
**Default**: `None`

Path to a log file for guard-core events. The directory is created automatically if it does not exist.

```python
SecurityConfig(
    custom_log_file="/var/log/guard-core/security.log",
    log_format="json",
)
```

When set, guard-core creates a file handler with the configured formatter. A console handler is also always attached, but it yields to the host's own root handlers whenever they exist; see "Avoiding duplicate log lines" below.

___

Log Setup
---------

The `setup_custom_logging()` function initializes the guard-core logger:

```python
def setup_custom_logging(
    log_file: str | None = None,
    log_format: str = "text",
) -> logging.Logger
```

This is called internally by the middleware during initialization. It:

1. Gets or creates the `"guard_core"` logger.
2. Clears existing handlers on the `"guard_core"` logger.
3. Adds a `StreamHandler` (console) with the configured formatter, always, carrying a filter that yields to the host's own root logger handlers; see "Avoiding duplicate log lines" below.
4. Optionally adds a `FileHandler` if `log_file` is specified, unfiltered, regardless of the root logger's state.
5. Sets the logger level to `INFO`.

___

Avoiding Duplicate Log Lines
-----------------------------

The `"guard_core"` logger keeps `propagate=True`, so its records always reach any handlers already attached to the process's root logger (a host calling `logging.basicConfig()`, for example). Guard's own console handler used to be attached unconditionally, so a host with root handlers configured saw every guard security event printed twice: once formatted by guard's handler, once via propagation through the host's.

`setup_custom_logging()` always attaches its own console handler to `"guard_core"`, but that handler carries a filter that checks `logging.getLogger().handlers` at the moment each record is emitted, not at setup time. Guard's console output yields to the host's root handlers whenever they exist, whichever was configured first: if the host configures its root logger before guard's `setup_custom_logging()` runs, or only afterward, guard's own console handler goes silent the moment root handlers exist, and the event reaches the host's handlers exactly once through propagation. Only while the root logger has no handlers at all does guard's own console handler emit, so output still appears when nothing else is configured to show it.

A host that wants guard's own formatted output (text or JSON) while running its own root logger handlers should either set `custom_log_file` (the file handler carries no such filter and is always attached) or attach a handler directly to the `"guard_core"` logger.

___

Log Activity Function
---------------------

The core logging function is `log_activity()` in `guard_core.utils`:

```python
async def log_activity(
    request: GuardRequest,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING",
) -> None
```

**Log types and their message formats**:

| `log_type`     | Message Format                                                    |
|----------------|-------------------------------------------------------------------|
| `"request"`    | `Request from {ip}: {method} {url} - Headers: {...}`             |
| `"suspicious"` | `Suspicious activity detected from {ip}: {method} {url} - Reason: {reason}` |
| Other          | `{Type} from {ip}: {method} {url} - Details: {reason}`          |

**Passive mode**: When `passive_mode=True` and `log_type="suspicious"`, the message is prefixed with `[PASSIVE MODE] Penetration attempt detected`.

**Level `None`**: When `level` is `None`, the function returns immediately without logging.

___

Security Event Logging
----------------------

Guard-core logs security events at specific levels:

| Event                    | Default Level | Source                    |
|--------------------------|--------------|---------------------------|
| Request blocked          | `WARNING`    | Various check implementations |
| Penetration attempt      | `WARNING`    | `SuspiciousActivityCheck` |
| IP banned                | `WARNING`    | `SuspiciousActivityCheck` |
| Rate limit exceeded      | `WARNING`    | `RateLimitManager`        |
| IP spoofing attempt      | `WARNING`    | `extract_client_ip()`     |
| CSP violation            | `WARNING`    | `SecurityHeadersManager`  |
| Emergency mode block     | `WARNING`    | `EmergencyModeCheck`      |
| Redis connection failure | `ERROR`      | `RedisManager`            |
| Pattern timeout          | `WARNING`    | `SusPatternsManager`      |
| Cloud IP range update    | `INFO`       | `CloudManager`            |

___

Log Sanitization
----------------

User-supplied values in log messages are sanitized by `_sanitize_for_log()`:

```python
def _sanitize_for_log(value: str) -> str:
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    sanitized = "".join(
        char if ord(char) >= 32 or char in "\t\n\r" else f"\\x{ord(char):02x}"
        for char in sanitized
    )
    return sanitized
```

This prevents log injection attacks through control characters in headers like `X-Forwarded-For`.
