---

title: Utilities API - Guard Core
description: Helper functions and utilities for logging, security checks, and request handling in guard-core
keywords: security utilities, logging functions, security checks, request handling, guard-core
---

Utilities
=========

The `utils` module provides various helper functions for security operations.

___

Logging Functions
-----------------

setup_custom_logging
---------------------

```python
def setup_custom_logging(
    log_file: str | None = None
) -> logging.Logger:
    """
    Setup custom logging for Guard Core.

    Configures a hierarchical logger that outputs to both console and file.
    Console output is ALWAYS enabled for visibility.
    File output is optional for persistence.

    Args:
        log_file: Optional path to log file. If None, only console output is enabled.
                  If provided, creates the directory if it doesn't exist.

    Returns:
        logging.Logger: Configured logger with namespace "guard_core"

    Note: This function is synchronous (not async).
    """
```

log_activity
------------

```python
async def log_activity(
    request: GuardRequest,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING"
):
    """
    Universal logging function for all types of requests and activities.
    """
```

Parameters:

- `request`: The FastAPI request object
- `logger`: The logger instance
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to enable passive mode logging format
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. If `None`, logging is disabled. Defaults to "WARNING".

This is a unified logging function that handles regular requests, suspicious activities, and passive mode logging.

___

Security Check Functions
------------------------

is_user_agent_allowed
---------------------

```python
async def is_user_agent_allowed(
    user_agent: str,
    config: SecurityConfig
) -> bool:
    """
    Check if user agent is allowed.
    """
```

check_ip_country
----------------

```python
async def check_ip_country(
    request: str | Request,
    config: SecurityConfig,
    ipinfo_db: IPInfoManager
) -> bool:
    """
    Check if IP is from a blocked country.
    """
```

is_ip_allowed
-------------

```python
async def is_ip_allowed(
    ip: str,
    config: SecurityConfig,
    ipinfo_db: IPInfoManager | None = None
) -> bool:
    """
    Check if IP address is allowed.
    """
```

The `ipinfo_db` parameter is now properly optional - it's only needed when country filtering is configured. If it's not provided when country filtering is configured, the function will work correctly but won't apply country filtering rules rules.

This function intelligently handles:

- Whitelist/blacklist checking
- Country filtering (only when IPInfoManager is provided)
- Cloud provider detection (only when cloud blocking is configured)

This selective processing aligns with Guard Core's smart resource loading to optimize performance.

detect_penetration_attempt
--------------------------

```python
async def detect_penetration_attempt(
    request: GuardRequest,
) -> tuple[bool, str]
```

Detect potential penetration attempts in the request using the enhanced Detection Engine.

This function analyzes various parts of the request (query params, body, path, headers) using the Detection Engine's components including pattern matching, semantic analysis, and performance monitoring.

Parameters:

- `request`: The FastAPI request object to analyze

Returns a tuple where:

- First element is a boolean: `True` if a potential attack is detected, `False` otherwise
- Second element is a string with details about what triggered the detection, or empty string if no attack detected

The Detection Engine provides:
- Timeout-protected pattern matching (configured via `detection_compiler_timeout` in SecurityConfig)
- Intelligent content preprocessing that preserves attack patterns
- Semantic analysis for obfuscated attacks (when enabled)
- Performance monitoring for pattern effectiveness

Example usage:

```python
from guard_core.protocols import GuardRequest
from guard_core.utils import detect_penetration_attempt

@app.post("/api/submit")
async def submit_data(request: GuardRequest):
    # Detection uses configuration from SecurityConfig
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    if is_suspicious:
        # Log the detection with details
        logger.warning(f"Attack detected: {trigger_info}")
        return {"error": "Suspicious activity detected"}
    return {"success": True}

@app.post("/api/critical")
async def critical_endpoint(request: GuardRequest):
    # Timeout protection is configured via SecurityConfig.detection_compiler_timeout
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    if is_suspicious:
        return {"error": "Security check failed"}
    return {"success": True}
```

extract_client_ip
-----------------

```python
async def extract_client_ip(
    request: GuardRequest,
    config: Any,
    agent_handler: AgentHandlerProtocol | None = None,
) -> str:
    """
    Securely extract the client IP address from the request, considering trusted proxies.

    This function implements a secure approach to IP extraction that protects against
    X-Forwarded-For header injection attacks.
    """
```

Parameters:

- `request`: The request object implementing `GuardRequest`
- `config`: The security configuration (must have `trusted_proxies` and `trusted_proxy_depth` attributes)
- `agent_handler`: Optional agent handler for sending IP spoofing telemetry events

This function provides a secure way to extract client IPs by:

1. Only trusting X-Forwarded-For headers from configured trusted proxies
2. Using the connecting IP when not from a trusted proxy
3. Properly handling proxy chains based on configured depth
4. Detecting and reporting IP spoofing attempts via the agent handler

___

Usage Examples
--------------

```python
from guard_core.utils import (
    setup_custom_logging,
    log_activity,
    detect_penetration_attempt
)

# Setup logging (synchronous function)
# Console only
logger = setup_custom_logging()  # or setup_custom_logging(None)

# Console + file
logger = setup_custom_logging("security.log")

# Log regular request
await log_activity(request, logger)

# Log suspicious activity
await log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="Suspicious pattern detected"
)

# Check for penetration attempts
is_suspicious, trigger_info = await detect_penetration_attempt(request)
```
