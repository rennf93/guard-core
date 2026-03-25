---

title: Security Headers
description: SecurityHeadersManager internals for CSP, HSTS, CORS, and default security headers in guard-core
keywords: security headers, csp, hsts, cors, owasp, guard-core
---

Security Headers
================

The `SecurityHeadersManager` applies HTTP security headers to responses following OWASP best practices. It supports Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), CORS, and a comprehensive set of default headers.

SecurityHeadersManager
----------------------

### Singleton

Thread-safe singleton using `threading.Lock` for the `__new__` double-checked locking pattern. Pre-instantiated as `security_headers_manager` at module level.

### Default Headers

Applied to every response when the manager is enabled:

| Header                           | Default Value                                    |
|----------------------------------|--------------------------------------------------|
| `X-Content-Type-Options`         | `nosniff`                                        |
| `X-Frame-Options`                | `SAMEORIGIN`                                     |
| `X-XSS-Protection`               | `1; mode=block`                                  |
| `Referrer-Policy`                | `strict-origin-when-cross-origin`                |
| `Permissions-Policy`             | `geolocation=(), microphone=(), camera=()`       |
| `X-Permitted-Cross-Domain-Policies` | `none`                                        |
| `X-Download-Options`             | `noopen`                                         |
| `Cross-Origin-Embedder-Policy`   | `require-corp`                                   |
| `Cross-Origin-Opener-Policy`     | `same-origin`                                    |
| `Cross-Origin-Resource-Policy`   | `same-origin`                                    |

### Configuration

The `configure()` method accepts keyword-only arguments:

```python
security_headers_manager.configure(
    enabled=True,
    csp={"default-src": ["'self'"], "script-src": ["'self'", "cdn.example.com"]},
    hsts_max_age=31536000,
    hsts_include_subdomains=True,
    hsts_preload=True,
    frame_options="DENY",
    content_type_options="nosniff",
    xss_protection="0",
    referrer_policy="no-referrer",
    permissions_policy="camera=()",
    custom_headers={"X-Custom": "value"},
    cors_origins=["https://example.com"],
    cors_allow_credentials=True,
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["Authorization"],
)
```

### CSP Configuration

CSP directives are stored as `dict[str, list[str]]` and serialized by `_build_csp()`:

```python
{"default-src": ["'self'"], "script-src": ["'self'", "'nonce-abc123'"]}
# becomes: "default-src 'self'; script-src 'self' 'nonce-abc123'"
```

!!! warning "Unsafe Sources"
    The manager logs a warning when CSP directives contain `'unsafe-inline'` or `'unsafe-eval'`.

### HSTS Configuration

HSTS is built from a config dictionary:

```python
{"max_age": 31536000, "include_subdomains": True, "preload": True}
# becomes: "max-age=31536000; includeSubDomains; preload"
```

**Preload validation**:

- `max_age` must be >= 31536000 (1 year) for preload. If not, preload is disabled with a warning.
- `includeSubDomains` must be `True` for preload. If not, it is force-enabled with a warning.

### CORS Configuration

```python
cors_config = {
    "origins": ["https://example.com"],
    "allow_credentials": True,
    "allow_methods": ["GET", "POST"],
    "allow_headers": ["Authorization"],
}
```

**Safety check**: If `origins` contains `"*"` and `allow_credentials` is `True`, credentials are force-disabled and the CORS configuration is blocked. This prevents a known security vulnerability.

### Getting Headers

```python
headers = await security_headers_manager.get_headers(request_path="/api/data")
```

**Caching**: Headers are cached per request path in a `TTLCache(maxsize=1000, ttl=300)`. Cache keys are SHA-256 hashes of normalized paths.

**Composition order**:

1. Default headers (copy)
2. CSP header (if configured)
3. HSTS header (if configured)
4. Custom headers (override any defaults)

### CORS Headers

```python
cors_headers = await security_headers_manager.get_cors_headers(origin="https://example.com")
```

Returns an empty dict if:

- CORS is not configured.
- The origin is not in the allowed list.
- Wildcard origin with credentials (security block).

### CSP Violation Reporting

```python
is_valid = await security_headers_manager.validate_csp_report(report_json)
```

Validates the structure of a CSP violation report (checks for `document-uri`, `violated-directive`, `blocked-uri` in the `csp-report` object) and logs the violation.

### Header Value Validation

All header values pass through `_validate_header_value()`:

- Rejects values containing `\r` or `\n` (HTTP response splitting prevention).
- Rejects values longer than 8192 bytes.
- Strips non-printable characters except tab.

### Redis Integration

Configuration (CSP, HSTS, custom headers) is cached to Redis with a 24-hour TTL. On initialization, the manager attempts to load cached configuration before applying defaults.
