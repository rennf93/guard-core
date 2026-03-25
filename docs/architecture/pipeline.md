---

title: Security Pipeline - Guard Core
description: Deep dive into the SecurityCheckPipeline chain of responsibility, all 17 security checks in execution order, the SecurityCheck base class, and extending the pipeline
keywords: guard-core, security pipeline, chain of responsibility, security checks, SecurityCheck, SecurityCheckPipeline
---

Security Pipeline
=================

The security pipeline is the heart of guard-core. It implements the **chain of responsibility** pattern: an ordered list of `SecurityCheck` instances, executed sequentially for every request. The first check that returns a non-`None` response short-circuits the pipeline and blocks the request.

___

SecurityCheckPipeline
---------------------

**Location**: `guard_core/core/checks/pipeline.py`

```python
class SecurityCheckPipeline:
    def __init__(self, checks: list[SecurityCheck]) -> None:
        self.checks = checks
        self.logger = logging.getLogger(__name__)

    async def execute(self, request: GuardRequest) -> GuardResponse | None:
        for check in self.checks:
            try:
                response = await check.check(request)
                if response is not None:
                    self.logger.info(
                        f"Request blocked by {check.check_name}",
                        extra={
                            "check": check.check_name,
                            "path": request.url_path,
                            "method": request.method,
                        },
                    )
                    return response

            except Exception as e:
                self.logger.error(
                    f"Error in security check {check.check_name}: {e}",
                    extra={
                        "check": check.check_name,
                        "path": request.url_path,
                        "method": request.method,
                    },
                    exc_info=True,
                )

                if hasattr(check.config, "fail_secure") and check.config.fail_secure:
                    self.logger.warning(
                        f"Blocking request due to check error "
                        f"in fail-secure mode: {check.check_name}"
                    )
                    return await check.create_error_response(
                        status_code=500,
                        default_message="Security check failed",
                    )

                continue

        return None
```

### Execution Semantics

1. Checks run **sequentially** in insertion order
2. A check returning `None` means "pass -- continue to next check"
3. A check returning a `GuardResponse` means "block -- stop pipeline and return this response"
4. If a check raises an exception, the pipeline catches it and either continues (fail-open) or blocks (fail-secure)
5. If all checks return `None`, the pipeline returns `None`, meaning the request is allowed

### Pipeline Management Methods

| Method | Signature | Description |
|---|---|---|
| `execute` | `async (request: GuardRequest) -> GuardResponse \| None` | Run all checks against the request |
| `add_check` | `(check: SecurityCheck) -> None` | Append a check to the end of the pipeline |
| `insert_check` | `(index: int, check: SecurityCheck) -> None` | Insert a check at a specific position |
| `remove_check` | `(check_name: str) -> bool` | Remove a check by name. Returns `True` if found |
| `get_check_names` | `() -> list[str]` | List all check names in execution order |
| `__len__` | `() -> int` | Number of checks in the pipeline |

___

SecurityCheck Base Class
------------------------

**Location**: `guard_core/core/checks/base.py`

Every security check extends this abstract base class:

```python
class SecurityCheck(ABC):
    def __init__(self, middleware: "GuardMiddlewareProtocol") -> None:
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    @abstractmethod
    async def check(self, request: GuardRequest) -> GuardResponse | None:
        pass

    @property
    @abstractmethod
    def check_name(self) -> str:
        pass

    async def send_event(
        self,
        event_type: str,
        request: GuardRequest,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return await self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        return self.config.passive_mode
```

### What a Check Must Implement

| Member | Type | Description |
|---|---|---|
| `check_name` | `@property -> str` | A unique identifier for the check (e.g. `"ip_security"`, `"rate_limit"`) |
| `check(request)` | `async -> GuardResponse \| None` | The check logic. Return `None` to pass, or a `GuardResponse` to block |

### What a Check Gets for Free

| Method | Description |
|---|---|
| `self.middleware` | Access to the `GuardMiddlewareProtocol` instance (event bus, route resolver, handlers) |
| `self.config` | Direct access to `SecurityConfig` |
| `self.logger` | The middleware's logger |
| `send_event(...)` | Shortcut for `self.middleware.event_bus.send_middleware_event(...)` |
| `create_error_response(status_code, message)` | Shortcut for `self.middleware.create_error_response(...)` |
| `is_passive_mode()` | Whether the engine is in passive (log-only) mode |

___

All 17 Checks in Execution Order
---------------------------------

The checks are listed here in the order they execute within the pipeline. This order matters -- earlier checks set up state that later checks depend on.

### 1. RouteConfigCheck

| | |
|---|---|
| **check_name** | `route_config` |
| **Module** | `guard_core.core.checks.implementations.route_config` |
| **Purpose** | Resolves the route-level decorator configuration and extracts the client IP |
| **Blocks?** | Never. Always returns `None` |
| **Side Effects** | Sets `request.state.route_config` and `request.state.client_ip` |

This check runs first because all subsequent checks depend on `request.state.client_ip` and `request.state.route_config`.

### 2. EmergencyModeCheck

| | |
|---|---|
| **check_name** | `emergency_mode` |
| **Module** | `guard_core.core.checks.implementations.emergency_mode` |
| **Purpose** | Blocks all requests when `config.emergency_mode = True`, except IPs in `config.emergency_whitelist` |
| **Blocks?** | Returns 503 for non-whitelisted IPs (unless passive mode) |

### 3. HttpsEnforcementCheck

| | |
|---|---|
| **check_name** | `https_enforcement` |
| **Module** | `guard_core.core.checks.implementations.https_enforcement` |
| **Purpose** | Redirects HTTP requests to HTTPS when `config.enforce_https = True` or route requires HTTPS |
| **Blocks?** | Returns 301 redirect to HTTPS URL |

### 4. RequestLoggingCheck

| | |
|---|---|
| **check_name** | `request_logging` |
| **Module** | `guard_core.core.checks.implementations.request_logging` |
| **Purpose** | Logs the incoming request if `config.log_request_level` is set |
| **Blocks?** | Never. Always returns `None` |

### 5. RequestSizeContentCheck

| | |
|---|---|
| **check_name** | `request_size_content` |
| **Module** | `guard_core.core.checks.implementations.request_size_content` |
| **Purpose** | Validates request body size and content type against route-level `max_request_size` and `allowed_content_types` |
| **Blocks?** | Returns 413 (payload too large) or 415 (unsupported media type) |

### 6. RequiredHeadersCheck

| | |
|---|---|
| **check_name** | `required_headers` |
| **Module** | `guard_core.core.checks.implementations.required_headers` |
| **Purpose** | Validates that required headers are present with expected values (from route config) |
| **Blocks?** | Returns 400 (bad request) |

### 7. AuthenticationCheck

| | |
|---|---|
| **check_name** | `authentication` |
| **Module** | `guard_core.core.checks.implementations.authentication` |
| **Purpose** | Validates authentication headers (Bearer, Basic, custom) based on route config |
| **Blocks?** | Returns 401 (unauthorized) |

### 8. ReferrerCheck

| | |
|---|---|
| **check_name** | `referrer` |
| **Module** | `guard_core.core.checks.implementations.referrer` |
| **Purpose** | Validates the `Referer` header against route-level allowed domains |
| **Blocks?** | Returns 403 (forbidden) |

### 9. CustomValidatorsCheck

| | |
|---|---|
| **check_name** | `custom_validators` |
| **Module** | `guard_core.core.checks.implementations.custom_validators` |
| **Purpose** | Executes route-level custom validator callables |
| **Blocks?** | Returns whatever the custom validator returns |

### 10. TimeWindowCheck

| | |
|---|---|
| **check_name** | `time_window` |
| **Module** | `guard_core.core.checks.implementations.time_window` |
| **Purpose** | Enforces time-of-day access restrictions from route config |
| **Blocks?** | Returns 403 (forbidden) |

### 11. CloudIpRefreshCheck

| | |
|---|---|
| **check_name** | `cloud_ip_refresh` |
| **Module** | `guard_core.core.checks.implementations.cloud_ip_refresh` |
| **Purpose** | Periodically refreshes cloud provider IP ranges based on `config.cloud_ip_refresh_interval` |
| **Blocks?** | Never. Always returns `None` |
| **Side Effects** | Triggers `middleware.refresh_cloud_ip_ranges()` when the interval has elapsed |

### 12. IpSecurityCheck

| | |
|---|---|
| **check_name** | `ip_security` |
| **Module** | `guard_core.core.checks.implementations.ip_security` |
| **Purpose** | IP ban checks, route-level IP whitelist/blacklist, country-based filtering, and global IP allowlist/blocklist |
| **Blocks?** | Returns 403 (forbidden) |
| **Side Effects** | Sets `request.state.is_whitelisted` |

### 13. CloudProviderCheck

| | |
|---|---|
| **check_name** | `cloud_provider` |
| **Module** | `guard_core.core.checks.implementations.cloud_provider` |
| **Purpose** | Blocks requests originating from cloud provider IP ranges (AWS, GCP, Azure) |
| **Blocks?** | Returns 403 (forbidden) |

### 14. UserAgentCheck

| | |
|---|---|
| **check_name** | `user_agent` |
| **Module** | `guard_core.core.checks.implementations.user_agent` |
| **Purpose** | Filters requests by user agent string against route-level and global blocklists |
| **Blocks?** | Returns 403 (forbidden) |

### 15. RateLimitCheck

| | |
|---|---|
| **check_name** | `rate_limit` |
| **Module** | `guard_core.core.checks.implementations.rate_limit` |
| **Purpose** | Enforces rate limits at four levels: endpoint-specific, route-level, geo-based, and global |
| **Blocks?** | Returns 429 (too many requests) |

!!! note "Rate limit evaluation order"
    The rate limit check evaluates in this priority: endpoint rate limits (from dynamic rules) > route rate limits (from decorators) > geo rate limits (from decorators) > global rate limit (from config). The first limit that is exceeded blocks the request.

### 16. SuspiciousActivityCheck

| | |
|---|---|
| **check_name** | `suspicious_activity` |
| **Module** | `guard_core.core.checks.implementations.suspicious_activity` |
| **Purpose** | Runs penetration attempt detection against the request URL, headers, query params, and body. Tracks suspicious request counts for auto-ban |
| **Blocks?** | Returns 403 (forbidden) |

### 17. CustomRequestCheck

| | |
|---|---|
| **check_name** | `custom_request` |
| **Module** | `guard_core.core.checks.implementations.custom_request` |
| **Purpose** | Executes the `config.custom_request_check` callable if provided |
| **Blocks?** | Returns whatever the custom check callable returns |

___

Fail-Open vs Fail-Secure
-------------------------

By default, the pipeline is **fail-open**: if a security check raises an unhandled exception, the pipeline logs the error and continues to the next check.

```python
except Exception as e:
    self.logger.error(...)

    if hasattr(check.config, "fail_secure") and check.config.fail_secure:
        return await check.create_error_response(
            status_code=500,
            default_message="Security check failed",
        )

    continue
```

The pipeline checks for `config.fail_secure` using `hasattr` — this attribute is **not** part of the standard `SecurityConfig` model. Adapters can enable fail-secure behavior by adding `fail_secure = True` to a `SecurityConfig` subclass or setting it dynamically. When truthy, any check exception results in a 500 response, blocking the request.

!!! tip "Choosing a failure mode"
    Use fail-open (the default) in most production environments to avoid availability issues from check bugs. Use fail-secure in high-security environments where blocking a request is preferable to allowing an unchecked one through.

___

Passive Mode
------------

When `SecurityConfig.passive_mode = True`, checks still evaluate fully and log violations, but they return `None` instead of a blocking `GuardResponse`. This is implemented at the individual check level:

```python
if not self.config.passive_mode:
    return await self.middleware.create_error_response(
        status_code=403,
        default_message="Forbidden",
    )

return None
```

Each check is responsible for honoring passive mode. The base class provides `is_passive_mode()` as a convenience method.

___

Adding a Custom Security Check
-------------------------------

To add a new check, create a class extending `SecurityCheck`, then register it in the pipeline.

### Step 1: Create the Check

```python
from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class ApiKeyCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "api_key"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            await self.send_event(
                event_type="authentication_failed",
                request=request,
                action_taken="request_blocked"
                if not self.is_passive_mode()
                else "logged_only",
                reason="Missing API key",
            )

            if not self.is_passive_mode():
                return await self.create_error_response(
                    status_code=401,
                    default_message="API key required",
                )

        return None
```

### Step 2: Register in the Pipeline

In your adapter's middleware, after building the default pipeline, add the check:

```python
from guard_core.core.checks.pipeline import SecurityCheckPipeline

pipeline = SecurityCheckPipeline(checks=[...])

pipeline.add_check(ApiKeyCheck(middleware))

pipeline.insert_check(7, ApiKeyCheck(middleware))
```

### Step 3: (Optional) Make It Removable

Other code can remove your check by name:

```python
pipeline.remove_check("api_key")
```

### Guidelines

- Always honor `self.is_passive_mode()` in your blocking logic
- Use `self.send_event(...)` to emit telemetry for agent integration
- Use `self.create_error_response(...)` instead of constructing responses directly -- this applies custom error messages, security headers, and response modifiers
- Access shared state through `self.middleware` (e.g. `self.middleware.rate_limit_handler`, `self.middleware.geo_ip_handler`)
- Read per-request state from `request.state` (e.g. `request.state.client_ip`, `request.state.route_config`)
