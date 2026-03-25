---

title: Check Implementations
description: All 17 built-in security checks in guard-core, their execution order, blocking conditions, and configuration
keywords: security checks, implementations, execution order, guard-core, pipeline
---

Check Implementations
=====================

Guard-core ships with 17 security checks that execute in a fixed order inside the `SecurityCheckPipeline`. Each check is a subclass of `SecurityCheck` located in `guard_core.core.checks.implementations`.

Execution Order
---------------

| #  | Check Name              | Class                     | Blocks? | Passive-Aware? |
|----|-------------------------|---------------------------|---------|----------------|
| 1  | `route_config`          | `RouteConfigCheck`        | Never   | N/A            |
| 2  | `emergency_mode`        | `EmergencyModeCheck`      | Yes     | Yes            |
| 3  | `https_enforcement`     | `HttpsEnforcementCheck`   | Yes     | Yes            |
| 4  | `request_logging`       | `RequestLoggingCheck`     | Never   | N/A            |
| 5  | `request_size_content`  | `RequestSizeContentCheck` | Yes     | Yes            |
| 6  | `required_headers`      | `RequiredHeadersCheck`    | Yes     | Yes            |
| 7  | `authentication`        | `AuthenticationCheck`     | Yes     | Yes            |
| 8  | `referrer`              | `ReferrerCheck`           | Yes     | Yes            |
| 9  | `custom_validators`     | `CustomValidatorsCheck`   | Yes     | Yes            |
| 10 | `time_window`           | `TimeWindowCheck`         | Yes     | Yes            |
| 11 | `cloud_ip_refresh`      | `CloudIpRefreshCheck`     | Never   | N/A            |
| 12 | `ip_security`           | `IpSecurityCheck`         | Yes     | Yes            |
| 13 | `cloud_provider`        | `CloudProviderCheck`      | Yes     | Yes            |
| 14 | `user_agent`            | `UserAgentCheck`          | Yes     | Yes            |
| 15 | `rate_limit`            | `RateLimitCheck`          | Yes     | Yes            |
| 16 | `suspicious_activity`   | `SuspiciousActivityCheck` | Yes     | Yes            |
| 17 | `custom_request`        | `CustomRequestCheck`      | Yes     | Yes            |

**Passive-Aware** means the check respects `SecurityConfig.passive_mode` -- it logs and emits events but does not return a blocking response.

___

1. RouteConfigCheck
-------------------

**Purpose**: Populates `request.state` with route configuration and client IP for all subsequent checks.

**Blocks**: Never. Always returns `None`.

**What it does**:

- Calls `middleware.route_resolver.get_route_config(request)` to resolve decorator-applied `RouteConfig`.
- Sets `request.state.route_config` (may be `None` if no decorator is applied).
- Calls `extract_client_ip()` and sets `request.state.client_ip`.

!!! important "Must Run First"
    Every other check reads `request.state.route_config` and `request.state.client_ip`. Removing or reordering this check will break the pipeline.

___

2. EmergencyModeCheck
---------------------

**Purpose**: Lockdown mode that blocks all traffic except whitelisted IPs.

**Blocks when**: `config.emergency_mode` is `True` and `client_ip` is not in `config.emergency_whitelist`.

**Response**: `503 Service temporarily unavailable`

**Configuration**:

| Field                 | Type         | Default  |
|-----------------------|-------------|----------|
| `emergency_mode`      | `bool`      | `False`  |
| `emergency_whitelist` | `list[str]` | `[]`     |

___

3. HttpsEnforcementCheck
------------------------

**Purpose**: Redirects HTTP requests to HTTPS.

**Blocks when**: HTTPS is required (globally or per-route) and the request is not HTTPS.

**Response**: `307` redirect to the HTTPS URL (via `response_factory.create_https_redirect`).

**HTTPS detection logic**:

1. Checks `request.url_scheme == "https"`.
2. If `trust_x_forwarded_proto` is enabled and the connecting IP is a trusted proxy, also checks `X-Forwarded-Proto: https`.

**Configuration**:

| Field                     | Type    | Default |
|---------------------------|---------|---------|
| `enforce_https`           | `bool`  | `False` |
| `trust_x_forwarded_proto` | `bool`  | `False` |
| `trusted_proxies`         | `list[str]` | `[]` |

Per-route: `RouteConfig.require_https`.

___

4. RequestLoggingCheck
----------------------

**Purpose**: Logs every incoming request.

**Blocks**: Never.

**Configuration**: `config.log_request_level` controls the log level. Set to `None` to disable.

___

5. RequestSizeContentCheck
--------------------------

**Purpose**: Validates request size and content type against route-level limits.

**Blocks when**:

- `Content-Length` exceeds `RouteConfig.max_request_size` (returns `413`).
- `Content-Type` is not in `RouteConfig.allowed_content_types` (returns `415`).

**Configuration**: Set via decorators on `RouteConfig`.

___

6. RequiredHeadersCheck
-----------------------

**Purpose**: Validates that required headers are present.

**Blocks when**: A header in `RouteConfig.required_headers` with value `"required"` is missing from the request.

**Response**: `400 Missing required header: {name}`

___

7. AuthenticationCheck
----------------------

**Purpose**: Validates the `Authorization` header format.

**Blocks when**: `RouteConfig.auth_required` is set and the header does not match the expected format (`"bearer"` expects `Bearer ...`, `"basic"` expects `Basic ...`).

**Response**: `401 Authentication required`

!!! note "Token Validation Not Included"
    This check only validates the header format, not the token itself. Actual token validation should be done in a custom validator or application logic.

___

8. ReferrerCheck
----------------

**Purpose**: Validates the `Referer` header against allowed domains.

**Blocks when**: `RouteConfig.require_referrer` is set and either the header is missing or the domain is not in the allowed list.

**Response**: `403 Referrer required` or `403 Invalid referrer`

___

9. CustomValidatorsCheck
------------------------

**Purpose**: Runs user-defined async validator functions.

**Blocks when**: Any validator in `RouteConfig.custom_validators` returns a non-`None` `GuardResponse`.

**Configuration**: Validators are `Callable[[GuardRequest], Awaitable[GuardResponse | None]]` functions registered via decorators.

___

10. TimeWindowCheck
-------------------

**Purpose**: Restricts access to specific time windows.

**Blocks when**: The current time falls outside the `start`/`end` range defined in `RouteConfig.time_restrictions`.

**Response**: `403 Access not allowed at this time`

**Time restriction format**:

```python
{
    "start": "09:00",
    "end": "17:00",
    "timezone": "US/Eastern"  # optional, defaults to UTC
}
```

Supports overnight ranges (e.g., `start: "22:00"`, `end: "06:00"`).

___

11. CloudIpRefreshCheck
-----------------------

**Purpose**: Periodically refreshes cloud provider IP ranges.

**Blocks**: Never.

**Triggers when**: `config.block_cloud_providers` is set and `cloud_ip_refresh_interval` seconds have elapsed since the last refresh.

___

12. IpSecurityCheck
-------------------

**Purpose**: Enforces IP-based access control at multiple levels.

**Evaluation order**:

1. **Banned IP check**: Consults `IPBanManager`. Returns `403 IP address banned`.
2. **Route-level IP restrictions**: If a `RouteConfig` exists, evaluates its `ip_blacklist`, `ip_whitelist`, `blocked_countries`, and `whitelist_countries`. Returns `403 Forbidden`.
3. **Global IP restrictions**: Evaluates `config.blacklist`, `config.whitelist`, `config.blocked_countries`, and `config.block_cloud_providers`. Returns `403 Forbidden`.

Also sets `request.state.is_whitelisted` for downstream checks (rate limiting and suspicious activity skip whitelisted IPs).

___

13. CloudProviderCheck
----------------------

**Purpose**: Blocks requests originating from cloud provider IP ranges (AWS, GCP, Azure).

**Blocks when**: `client_ip` belongs to a blocked cloud provider's network and the check is not bypassed.

**Response**: `403 Cloud provider IP not allowed`

**Skips**: Whitelisted IPs (`request.state.is_whitelisted`).

___

14. UserAgentCheck
------------------

**Purpose**: Blocks requests from matching user agents.

**Blocks when**: The `User-Agent` header matches any pattern in `RouteConfig.blocked_user_agents` or `config.blocked_user_agents` (case-insensitive regex).

**Response**: `403 User-Agent not allowed`

**Skips**: Whitelisted IPs.

___

15. RateLimitCheck
------------------

**Purpose**: Enforces request rate limits using a sliding window algorithm.

**Evaluation order** (first match wins):

1. **Endpoint-specific rate limits** from `config.endpoint_rate_limits` (set by dynamic rules).
2. **Route-level rate limits** from `RouteConfig.rate_limit` and `RouteConfig.rate_limit_window`.
3. **Geo-based rate limits** from `RouteConfig.geo_rate_limits`.
4. **Global rate limits** from `config.rate_limit` and `config.rate_limit_window`.

**Response**: `429 Too many requests`

**Skips**: Whitelisted IPs and bypassed routes.

___

16. SuspiciousActivityCheck
---------------------------

**Purpose**: Detects penetration attempts (SQLi, XSS, command injection, path traversal, etc.).

**Blocks when**: `detect_penetration_patterns()` finds a threat in query parameters, URL path, headers, or request body.

**Behavior**:

- Increments `suspicious_request_counts[client_ip]`.
- When the count reaches `auto_ban_threshold`, bans the IP via `IPBanManager` for `auto_ban_duration` seconds.
- Returns `403 IP has been banned` if auto-banned, otherwise `400 Suspicious activity detected`.

**Skips**: Whitelisted IPs and routes with detection disabled via decorator.

___

17. CustomRequestCheck
----------------------

**Purpose**: Runs a global user-defined request check function.

**Blocks when**: `config.custom_request_check` returns a non-`None` `GuardResponse`.

**Configuration**: `SecurityConfig.custom_request_check` is a `Callable[[GuardRequest], Awaitable[GuardResponse | None]]`.

___

Implementing a Custom Check
---------------------------

To add a new check, create a subclass of `SecurityCheck`:

```python
from guard_core.core.checks.base import SecurityCheck
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse


class GeoFenceCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "geo_fence"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        client_ip = getattr(request.state, "client_ip", None)
        if not client_ip:
            return None

        if self._is_outside_fence(client_ip):
            if self.is_passive_mode():
                self.logger.warning(f"Geo-fence violation: {client_ip}")
                return None
            return await self.create_error_response(403, "Access denied")

        return None
```

Register it in the pipeline during middleware initialization:

```python
pipeline.insert_check(12, GeoFenceCheck(middleware))
```
