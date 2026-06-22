---

title: Security Decorators API - Guard Core
description: API reference for guard-core's security decorator system including SecurityDecorator, RouteConfig, and all mixins
keywords: security decorators, guard-core, route config, access control, authentication
---

Security Decorators
===================

The decorators module provides route-level security controls that can be applied to individual endpoints. These decorators offer fine-grained control over security policies on a per-route basis, complementing the global security pipeline. Framework adapters expose these decorators to their users through their own decorator interfaces.

___

Overview
--------

Security decorators allow you to:

- Apply specific security rules to individual routes
- Override global security settings for specific endpoints
- Combine multiple security measures in a clean, readable way
- Implement behavioral analysis and monitoring per endpoint

___

Main Decorator Class
--------------------

### SecurityDecorator

The main decorator class that combines all security capabilities. This is the primary class you'll use in your application.

**Example Usage:**

```python
from guard_core import SecurityConfig
from guard_core.decorators import SecurityDecorator

config = SecurityConfig()
guard_deco = SecurityDecorator(config)

@app.get("/api/sensitive")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.block_countries(["CN", "RU"])
def sensitive_endpoint():
    return {"data": "sensitive"}
```

___

Base Classes
------------

### BaseSecurityDecorator

Base class providing core decorator functionality and route configuration management.

### RouteConfig

Configuration class that stores security settings for individual routes.

___

Mixin Classes
-------------

The decorator system uses mixins to organize different types of security features:

### AccessControlMixin

Provides IP-based and geographic access control decorators.

**Available Decorators:**

- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(countries=[])` - Block specific countries
- `@guard_deco.allow_countries(countries=[])` - Allow only specific countries
- `@guard_deco.block_clouds(providers=[])` - Block cloud provider IPs
- `@guard_deco.bypass(checks=[])` - Bypass specific security checks

### AuthenticationMixin

Provides authentication and authorization decorators.

**Available Decorators:**

- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers(headers={})` - Require specific headers

### RateLimitingMixin

Provides rate limiting decorators.

**Available Decorators:**

- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={})` - Geographic rate limiting

### BehavioralMixin

Provides behavioral analysis and monitoring decorators.

**Available Decorators:**

- `@guard_deco.usage_monitor(max_calls, window, action)` - Monitor endpoint usage
- `@guard_deco.return_monitor(pattern, max_occurrences, window, action)` - Monitor return patterns
- `@guard_deco.behavior_analysis(rules=[])` - Apply multiple behavioral rules
- `@guard_deco.suspicious_frequency(max_frequency, window, action)` - Detect suspicious frequency

### ContentFilteringMixin

Provides content and request filtering decorators.

**Available Decorators:**

- `@guard_deco.block_user_agents(patterns=[])` - Block user agent patterns
- `@guard_deco.content_type_filter(allowed_types=[])` - Filter content types
- `@guard_deco.max_request_size(size_bytes)` - Limit request size
- `@guard_deco.require_referrer(allowed_domains=[])` - Require specific referrers
- `@guard_deco.custom_validation(validator)` - Add custom validation logic
- `@guard_deco.detection_exclusion(headers=None, params=None, body_fields=None, categories=None)` - Per-route detection scoping

**`detection_exclusion` semantics**

```python
def detection_exclusion(
    self,
    headers: set[str] | None = None,
    params: set[str] | None = None,
    body_fields: set[str] | None = None,
    categories: set[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    ...
```

All four kwargs are optional `set[str] | None`. Passing `None` (or omitting) leaves the corresponding `RouteConfig` field unset — the route inherits the global `SecurityConfig` value at request time. Passing a set replaces the inherited value at this route only.

- `headers` — header names skipped by detection. Merged with `SecurityConfig.excluded_detection_headers` and the hardcoded default exclusion list.
- `params` — query parameter names skipped by detection. Replaces (does not merge with) the global set when set.
- `body_fields` — top-level JSON body keys skipped by detection. Replaces the global set when set.
- `categories` — categories the regex scanner runs at this route. Replaces the global `enabled_detection_categories`. Custom user patterns always run regardless.

```python
@app.post("/api/markdown-editor/save")
@guard_deco.detection_exclusion(
    body_fields={"content", "draft"},
    categories={"sqli", "cmd_injection"},
)
def save_markdown():
    return {"saved": True}
```

### AdvancedMixin

Provides advanced detection and time-based decorators.

**Available Decorators:**

- `@guard_deco.time_window(start_time, end_time, timezone)` - Time-based access control
- `@guard_deco.suspicious_detection(enabled=True)` - Toggle suspicious pattern detection
- `@guard_deco.honeypot_detection(trap_fields=[])` - Detect bots using honeypot fields

___

Utility Functions
-----------------

### get_route_decorator_config

```python
def get_route_decorator_config(
    request: GuardRequest,
    decorator_handler: BaseSecurityDecorator,
) -> RouteConfig | None:
    """
    Extract route security configuration from the current request.
    """
```

___

Integration with Middleware
---------------------------

The decorators work in conjunction with the SecurityMiddleware to provide comprehensive protection:

1. **Route Configuration**: Decorators configure route-specific settings
2. **Middleware Processing**: SecurityMiddleware reads decorator configurations and applies them
3. **Override Behavior**: Route-specific settings can override global middleware settings

**Example Integration:**

```python
from guard_core import SecurityConfig
from guard_core.decorators import SecurityDecorator

config = SecurityConfig(
    enable_ip_banning=True,
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=3600
)

guard_deco = SecurityDecorator(config)

@guard_deco.rate_limit(requests=10, window=300)
@app.get("/api/limited")
def limited_endpoint():
    return {"data": "limited"}

@app.get("/api/public")
def public_endpoint():
    return {"data": "public"}

app.state.guard_decorator = guard_deco
```

___

Best Practices
--------------

### Decorator Order

Apply decorators in logical order, with more specific restrictions first:

```python
@app.post("/api/admin/sensitive")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.rate_limit(requests=5, window=3600)
@guard_deco.suspicious_detection(enabled=True)
def admin_endpoint():
    return {"status": "admin action"}
```

### Combining Behavioral Analysis

Use multiple behavioral decorators for comprehensive monitoring:

```python
@app.get("/api/rewards")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="alert")
def rewards_endpoint():
    return {"reward": "rare_item", "value": 1000}
```

### Geographic and Cloud Controls

Combine geographic and cloud provider controls:

```python
@app.get("/api/restricted")
@guard_deco.allow_countries(["US", "CA", "GB"])
@guard_deco.block_clouds(["AWS", "GCP"])
def restricted_endpoint():
    return {"data": "geo-restricted"}
```

### Content Filtering

Apply content filtering for upload endpoints:

```python
@app.post("/api/upload")
@guard_deco.content_type_filter(["image/jpeg", "image/png"])
@guard_deco.max_request_size(5 * 1024 * 1024)
@guard_deco.require_referrer(["myapp.com"])
def upload_endpoint():
    return {"status": "uploaded"}
```

___

Error Handling
--------------

Decorators integrate with the middleware's error handling system. When decorator conditions are not met, appropriate HTTP responses are returned:

### 403 Forbidden

IP restrictions, country blocks, authentication failures

### 429 Too Many Requests

Rate limiting violations

### 400 Bad Request

Content type mismatches, missing headers

### 413 Payload Too Large

Request size limits exceeded

___

Configuration Priority
----------------------

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows for flexible override behavior where routes can customize their security requirements while maintaining global defaults.
