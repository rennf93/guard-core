---

title: Protocols
description: The protocol interfaces that adapters must implement to integrate guard-core with any Python web framework
keywords: protocols, guard request, guard response, middleware protocol, adapter development, guard-core
---

Protocols
=========

Protocols are the most important API surface for adapter developers. Guard-core uses Python `Protocol` classes (PEP 544) to define the contracts that adapters must satisfy. All protocols are `@runtime_checkable`.

___

GuardRequest
------------

The request protocol defines how guard-core reads incoming request data. Adapters must wrap their framework's request object to satisfy this interface.

```python
@runtime_checkable
class GuardRequest(Protocol):
    @property
    def url_path(self) -> str: ...
    @property
    def url_scheme(self) -> str: ...
    @property
    def url_full(self) -> str: ...
    def url_replace_scheme(self, scheme: str) -> str: ...
    @property
    def method(self) -> str: ...
    @property
    def client_host(self) -> str | None: ...
    @property
    def headers(self) -> Mapping[str, str]: ...
    @property
    def query_params(self) -> Mapping[str, str]: ...
    async def body(self) -> bytes: ...
    @property
    def state(self) -> Any: ...
    @property
    def scope(self) -> dict[str, Any]: ...
```

### Member Details

| Member              | Return Type          | Description                                                   |
|---------------------|---------------------|---------------------------------------------------------------|
| `url_path`          | `str`               | The path component of the URL (e.g., `"/api/users"`).         |
| `url_scheme`        | `str`               | The URL scheme (`"http"` or `"https"`).                       |
| `url_full`          | `str`               | The full URL string including scheme, host, path, and query.  |
| `url_replace_scheme`| `str`               | Returns the full URL with the scheme replaced. Used for HTTPS redirects. |
| `method`            | `str`               | The HTTP method (`"GET"`, `"POST"`, etc.).                    |
| `client_host`       | `str \| None`       | The connecting client's IP address. `None` if unavailable.    |
| `headers`           | `Mapping[str, str]` | Request headers as a read-only mapping. Case handling depends on adapter. |
| `query_params`      | `Mapping[str, str]` | URL query parameters as a read-only mapping.                  |
| `body()`            | `bytes` (async)     | The raw request body. May be called multiple times by detection checks. |
| `state`             | `Any`               | A mutable state object for passing data between checks. Must support attribute assignment. |
| `scope`             | `dict[str, Any]`    | ASGI-style scope dict. Used for route resolution (`scope["route"]`). |

### Implementation Notes

**`state`**: Guard-core sets these attributes on `state` during pipeline execution:

- `state.route_config` -- `RouteConfig | None`
- `state.client_ip` -- `str`
- `state.is_whitelisted` -- `bool`

The adapter's `state` object must support dynamic attribute assignment (e.g., a simple namespace or the framework's built-in state).

**`scope`**: Must include a `"route"` key with an object that has an `endpoint` attribute for decorator resolution. If the framework does not have route objects in scope, decorator-based features will not activate.

**`body()`**: The detection engine calls `body()` to scan request bodies for threats. Adapters should ensure the body is buffered and can be read multiple times (not consumed on first read).

**`headers`**: Must be iterable via `.items()` for header scanning. Guard-core reads headers case-insensitively in many places (e.g., `headers.get("User-Agent")`), but the mapping itself does not need to be case-insensitive.

___

GuardResponse
-------------

The response protocol defines how guard-core reads and modifies outgoing responses.

```python
@runtime_checkable
class GuardResponse(Protocol):
    @property
    def status_code(self) -> int: ...
    @property
    def headers(self) -> MutableMapping[str, str]: ...
    @property
    def body(self) -> bytes | None: ...
```

### Member Details

| Member        | Return Type               | Description                                           |
|---------------|--------------------------|-------------------------------------------------------|
| `status_code` | `int`                    | HTTP status code.                                     |
| `headers`     | `MutableMapping[str, str]`| Response headers. Must be mutable for security header injection. |
| `body`        | `bytes \| None`          | Response body bytes. Used by behavioral return pattern matching. |

___

GuardResponseFactory
--------------------

Adapters must provide a factory that creates framework-native response objects.

```python
@runtime_checkable
class GuardResponseFactory(Protocol):
    def create_response(self, content: str, status_code: int) -> GuardResponse: ...
    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse: ...
```

| Method                    | Purpose                                                    |
|---------------------------|------------------------------------------------------------|
| `create_response`         | Creates a plain text/JSON error response.                  |
| `create_redirect_response`| Creates an HTTP redirect (used for HTTPS enforcement).     |

___

GuardMiddlewareProtocol
-----------------------

Defines the interface that the adapter's middleware class must expose to the security check pipeline.

```python
@runtime_checkable
class GuardMiddlewareProtocol(Protocol):
    config: SecurityConfig
    logger: logging.Logger
    last_cloud_ip_refresh: int
    suspicious_request_counts: dict[str, int]

    @property
    def event_bus(self) -> Any: ...
    @property
    def route_resolver(self) -> Any: ...
    @property
    def response_factory(self) -> Any: ...
    @property
    def rate_limit_handler(self) -> Any: ...
    @property
    def agent_handler(self) -> Any: ...
    @property
    def geo_ip_handler(self) -> Any: ...
    @property
    def guard_response_factory(self) -> Any: ...

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse: ...

    async def refresh_cloud_ip_ranges(self) -> None: ...
```

### Attributes

| Attribute                   | Type                  | Description                                       |
|-----------------------------|-----------------------|---------------------------------------------------|
| `config`                    | `SecurityConfig`      | The security configuration.                       |
| `logger`                    | `logging.Logger`      | Logger instance for the middleware.                |
| `last_cloud_ip_refresh`     | `int`                 | Timestamp of the last cloud IP refresh.           |
| `suspicious_request_counts` | `dict[str, int]`      | Per-IP suspicious request counters for auto-ban.  |

### Properties

| Property                | Purpose                                                 |
|-------------------------|---------------------------------------------------------|
| `event_bus`             | `SecurityEventBus` for emitting security events.        |
| `route_resolver`        | `RouteConfigResolver` for decorator resolution.         |
| `response_factory`      | `ErrorResponseFactory` for creating error responses.    |
| `rate_limit_handler`    | `RateLimitManager` instance.                            |
| `agent_handler`         | Agent handler or `None`.                                |
| `geo_ip_handler`        | `GeoIPHandler` or `None`.                               |
| `guard_response_factory`| `GuardResponseFactory` from the adapter.                |

___

GeoIPHandler
------------

Protocol for geolocation services. Adapters can provide any implementation (MaxMind, IPInfo, custom).

```python
@runtime_checkable
class GeoIPHandler(Protocol):
    @property
    def is_initialized(self) -> bool: ...
    async def initialize(self) -> None: ...
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None: ...
    def get_country(self, ip: str) -> str | None: ...
```

| Method            | Description                                         |
|-------------------|-----------------------------------------------------|
| `is_initialized`  | Whether the handler has been initialized.           |
| `initialize()`    | Perform async initialization (e.g., download DB).   |
| `get_country(ip)` | Return ISO country code for the IP, or `None`.      |

___

RedisHandlerProtocol
--------------------

Protocol for Redis operations. Matches the `RedisManager` interface.

```python
@runtime_checkable
class RedisHandlerProtocol(Protocol):
    async def get_key(self, namespace: str, key: str) -> Any: ...
    async def set_key(self, namespace: str, key: str, value: Any, ttl: int | None = None) -> bool | None: ...
    async def delete(self, namespace: str, key: str) -> int | None: ...
    async def keys(self, pattern: str) -> list[str] | None: ...
    async def initialize(self) -> None: ...
    def get_connection(self) -> AsyncContextManager[Any]: ...
```

___

AgentHandlerProtocol
--------------------

Protocol for the Guard Agent telemetry system.

```python
@runtime_checkable
class AgentHandlerProtocol(Protocol):
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def send_event(self, event: Any) -> None: ...
    async def send_metric(self, metric: Any) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def flush_buffer(self) -> None: ...
    async def get_dynamic_rules(self) -> Any | None: ...
    async def health_check(self) -> bool: ...
```
