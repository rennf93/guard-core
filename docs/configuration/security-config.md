---

title: SecurityConfig Reference
description: Complete reference for every SecurityConfig field in guard-core, grouped by category with types, defaults, and descriptions
keywords: security config, configuration, pydantic, guard-core
---

SecurityConfig Reference
========================

`SecurityConfig` is a Pydantic `BaseModel` that controls all guard-core behavior. Adapter developers should expose relevant fields to their users while keeping internal fields (agent, dynamic rules) as implementation details.

Core Settings
-------------

| Field                     | Type                        | Default  | Description                                            |
|---------------------------|-----------------------------|----------|--------------------------------------------------------|
| `passive_mode`            | `bool`                      | `False`  | Log-only mode. Logs and emits events but never blocks. |
| `exclude_paths`           | `list[str]`                 | See below| Paths excluded from all security checks.               |
| `custom_error_responses`  | `dict[int, str]`            | `{}`     | Override error messages for specific HTTP status codes. |
| `enforce_https`           | `bool`                      | `False`  | Redirect HTTP requests to HTTPS globally.              |
| `custom_request_check`    | `Callable \| None`          | `None`   | Global async function for custom request validation.   |
| `custom_response_modifier`| `Callable \| None`          | `None`   | Global async function to modify responses.             |

**Default `exclude_paths`**: `["/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"]`

!!! tip "Adapter Exposure"
    All core settings should be exposed to end users. `passive_mode` is particularly useful for deployment rollouts.

___

Proxy Configuration
-------------------

| Field                     | Type         | Default  | Description                                            |
|---------------------------|-------------|----------|--------------------------------------------------------|
| `trusted_proxies`         | `list[str]` | `[]`     | Trusted proxy IPs or CIDR ranges for X-Forwarded-For.  |
| `trusted_proxy_depth`     | `int`       | `1`      | Number of proxies in the X-Forwarded-For chain.        |
| `trust_x_forwarded_proto` | `bool`      | `False`  | Trust X-Forwarded-Proto header for HTTPS detection.    |

**Validators**:

- `trusted_proxies`: Each entry is validated as a valid IP address or CIDR range.
- `trusted_proxy_depth`: Must be >= 1.

___

IP Management
-------------

| Field                | Type              | Default           | Description                                    |
|----------------------|-------------------|-------------------|------------------------------------------------|
| `whitelist`          | `list[str] \| None` | `None`          | Allowed IPs/CIDRs. `None` disables (allow all).|
| `blacklist`          | `list[str]`       | `[]`              | Blocked IPs/CIDRs.                             |
| `whitelist_countries`| `list[str]`       | `[]`              | Country codes always allowed.                  |
| `blocked_countries`  | `list[str]`       | `[]`              | Country codes always blocked.                  |
| `blocked_user_agents`| `list[str]`       | `[]`              | Regex patterns for blocked user agents.        |
| `enable_ip_banning`  | `bool`            | `True`            | Enable automatic IP banning.                   |
| `auto_ban_threshold` | `int`             | `10`              | Suspicious requests before auto-ban.           |
| `auto_ban_duration`  | `int`             | `3600`            | Ban duration in seconds.                       |

**Validators**:

- `whitelist` and `blacklist`: Each entry validated as a valid IP or CIDR range via `ipaddress.ip_address()` / `ip_network()`.

!!! warning "Whitelist Semantics"
    `whitelist=None` means "no whitelist" (all IPs pass). `whitelist=[]` means "empty whitelist" (no IPs pass). Adapter developers should document this distinction.

___

Geolocation
-----------

| Field              | Type              | Default | Description                                         |
|--------------------|-------------------|---------|-----------------------------------------------------|
| `geo_ip_handler`   | `GeoIPHandler \| None` | `None`  | Custom geolocation handler implementing the protocol.|
| `ipinfo_token`     | `str \| None`     | `None`  | **Deprecated.** IPInfo API token.                   |
| `ipinfo_db_path`   | `Path \| None`    | `data/ipinfo/country_asn.mmdb` | **Deprecated.** Path to IPInfo database. |

**Model validator**: If `blocked_countries` or `whitelist_countries` are set, `geo_ip_handler` must be provided (or `ipinfo_token` for backward compatibility). Raises `ValueError` otherwise.

___

Rate Limiting
-------------

| Field                 | Type             | Default | Description                                        |
|-----------------------|------------------|---------|---------------------------------------------------|
| `enable_rate_limiting`| `bool`           | `True`  | Master switch for rate limiting.                   |
| `rate_limit`          | `int`            | `10`    | Maximum requests per window (global).              |
| `rate_limit_window`   | `int`            | `60`    | Window duration in seconds (global).               |
| `endpoint_rate_limits`| `dict[str, tuple[int, int]]` | `{}` | Per-endpoint overrides `{path: (limit, window)}`. |

___

Cloud Provider Blocking
-----------------------

| Field                      | Type             | Default | Description                              |
|----------------------------|------------------|---------|------------------------------------------|
| `block_cloud_providers`    | `set[str] \| None` | `None`  | Providers to block: `"AWS"`, `"GCP"`, `"Azure"`. |
| `cloud_ip_refresh_interval`| `int`            | `3600`  | Seconds between IP range refreshes (60-86400). |

**Validator**: `block_cloud_providers` is filtered to only include valid values `{"AWS", "GCP", "Azure"}`.

___

Security Headers
----------------

| Field              | Type                   | Default      | Description                          |
|--------------------|------------------------|--------------|--------------------------------------|
| `security_headers` | `dict[str, Any] \| None` | See below  | Security headers configuration dict. |

**Default structure**:

```python
{
    "enabled": True,
    "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
    "csp": None,
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "1; mode=block",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None,
}
```

___

CORS
----

| Field                    | Type         | Default               | Description                            |
|--------------------------|-------------|----------------------|----------------------------------------|
| `enable_cors`            | `bool`      | `False`              | Enable CORS header injection.          |
| `cors_allow_origins`     | `list[str]` | `["*"]`              | Allowed origins.                       |
| `cors_allow_methods`     | `list[str]` | `["GET", "POST", ...]`| Allowed HTTP methods.                 |
| `cors_allow_headers`     | `list[str]` | `["*"]`              | Allowed request headers.               |
| `cors_allow_credentials` | `bool`      | `False`              | Allow credentials in CORS requests.    |
| `cors_expose_headers`    | `list[str]` | `[]`                 | Headers exposed in CORS responses.     |
| `cors_max_age`           | `int`       | `600`                | Preflight cache duration in seconds.   |

___

Redis
-----

| Field          | Type          | Default                   | Description                           |
|----------------|---------------|---------------------------|---------------------------------------|
| `enable_redis` | `bool`        | `True`                    | Master switch for Redis.              |
| `redis_url`    | `str \| None` | `"redis://localhost:6379"`| Redis connection URL.                 |
| `redis_prefix` | `str`         | `"guard_core:"`           | Key prefix for namespace isolation.   |

___

Detection Engine
----------------

| Field                               | Type    | Default | Range         | Description                                  |
|-------------------------------------|---------|---------|---------------|----------------------------------------------|
| `enable_penetration_detection`      | `bool`  | `True`  | N/A           | Master switch for threat detection.          |
| `detection_compiler_timeout`        | `float` | `2.0`   | 0.1 - 10.0   | Timeout for pattern compilation/matching (s).|
| `detection_max_content_length`      | `int`   | `10000` | 1000 - 100000 | Maximum content length for detection.        |
| `detection_preserve_attack_patterns`| `bool`  | `True`  | N/A           | Preserve attack patterns during truncation.  |
| `detection_semantic_threshold`      | `float` | `0.7`   | 0.0 - 1.0    | Threshold for semantic attack detection.     |
| `detection_anomaly_threshold`       | `float` | `3.0`   | 1.0 - 10.0   | Std deviations for anomaly detection.        |
| `detection_slow_pattern_threshold`  | `float` | `0.1`   | 0.01 - 1.0   | Seconds to consider a pattern slow.          |
| `detection_monitor_history_size`    | `int`   | `1000`  | 100 - 10000   | Recent metrics to keep in history.           |
| `detection_max_tracked_patterns`    | `int`   | `1000`  | 100 - 5000    | Maximum patterns to track for performance.   |

___

Logging
-------

| Field                 | Type                                            | Default    | Description                              |
|-----------------------|-------------------------------------------------|------------|------------------------------------------|
| `log_suspicious_level`| `"INFO" \| "DEBUG" \| "WARNING" \| "ERROR" \| "CRITICAL" \| None` | `"WARNING"` | Log level for suspicious requests. `None` disables. |
| `log_request_level`   | Same as above                                   | `None`     | Log level for all requests. `None` disables. |
| `log_format`          | `"text" \| "json"`                              | `"text"`   | Log output format.                       |
| `custom_log_file`     | `str \| None`                                   | `None`     | Path to a custom log file.               |

___

Agent / Telemetry
-----------------

!!! note "Internal Configuration"
    Agent fields are typically not exposed to end users. They are used for Guard Agent SaaS integration.

| Field                    | Type          | Default                           | Description                         |
|--------------------------|---------------|-----------------------------------|-------------------------------------|
| `enable_agent`           | `bool`        | `False`                           | Enable Guard Agent telemetry.       |
| `agent_api_key`          | `str \| None` | `None`                            | API key for the SaaS platform.      |
| `agent_endpoint`         | `str`         | `"https://api.fastapi-guard.com"` | Agent endpoint URL.                 |
| `agent_project_id`       | `str \| None` | `None`                            | Project identifier.                 |
| `agent_buffer_size`      | `int`         | `100`                             | Events to buffer before flush.      |
| `agent_flush_interval`   | `int`         | `30`                              | Seconds between automatic flushes.  |
| `agent_enable_events`    | `bool`        | `True`                            | Send security events.               |
| `agent_enable_metrics`   | `bool`        | `True`                            | Send performance metrics.           |
| `agent_timeout`          | `int`         | `30`                              | HTTP request timeout in seconds.    |
| `agent_retry_attempts`   | `int`         | `3`                               | Retry attempts for failed requests. |

**Validator**: `agent_api_key` is required when `enable_agent` is `True`.

___

Dynamic Rules
-------------

| Field                   | Type   | Default | Description                                     |
|-------------------------|--------|---------|-------------------------------------------------|
| `enable_dynamic_rules`  | `bool` | `False` | Enable dynamic rule updates from SaaS platform. |
| `dynamic_rule_interval` | `int`  | `300`   | Seconds between rule update checks.             |
| `emergency_mode`        | `bool` | `False` | Emergency lockdown mode (set by dynamic rules). |
| `emergency_whitelist`   | `list[str]` | `[]`| Emergency whitelist IPs (set by dynamic rules). |

**Validator**: `enable_agent` must be `True` when `enable_dynamic_rules` is `True`.

___

Validators
----------

`SecurityConfig` includes Pydantic validators that run on instantiation:

| Validator | Fields | Behavior |
|-----------|--------|----------|
| `validate_ip_lists` | `whitelist`, `blacklist` | Validates IP addresses and CIDR ranges. Raises `ValueError` on invalid entries. |
| `validate_trusted_proxies` | `trusted_proxies` | Validates proxy IPs and CIDR ranges. Raises `ValueError` on invalid entries. |
| `validate_proxy_depth` | `trusted_proxy_depth` | Must be >= 1. Raises `ValueError` otherwise. |
| `validate_cloud_providers` | `block_cloud_providers` | Silently filters invalid providers — only `"AWS"`, `"GCP"`, `"Azure"` are kept. |
| `validate_geo_ip_handler_exists` | model-level | Requires `geo_ip_handler` when `blocked_countries` or `whitelist_countries` is set. Falls back to `IPInfoManager` if `ipinfo_token` is provided. |
| `validate_agent_config` | model-level | Requires `agent_api_key` when `enable_agent` is `True`. Requires `enable_agent` when `enable_dynamic_rules` is `True`. |

!!! warning "Silent filtering"
    `validate_cloud_providers` silently drops unrecognized provider names. `{"AWS", "InvalidProvider"}` becomes `{"AWS"}` without raising an error.
