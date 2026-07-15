---

title: Redis Integration
description: RedisManager internals for connection pooling, auto-reconnection, safe operations, and key namespacing in guard-core
keywords: redis, connection pooling, distributed state, key namespacing, guard-core
---

Redis Integration
=================

Guard-core uses Redis for distributed state management across multiple application instances. The `RedisManager` handler provides connection management, namespaced key operations, and fault-tolerant wrappers.

RedisManager
------------

### Construction

```python
class RedisManager:
    def __new__(cls, config: SecurityConfig) -> "RedisManager":
        cls._instance = super().__new__(cls)
        cls._instance.config = config
        cls._instance._closed = False
        cls._instance.agent_handler = None
        return cls._instance
```

Unlike other handlers, `RedisManager` creates a new instance on every construction. The `redis_handler` module-level variable is the class itself (not an instance), allowing deferred instantiation with a config.

### Connection Lifecycle

**Initialize**:

```python
redis_manager = RedisManager(config)
await redis_manager.initialize()
```

Creates a `redis.asyncio.Redis` connection from `config.redis_url` with `decode_responses=True`, applying the configured socket timeouts (`redis_socket_timeout`, `redis_socket_connect_timeout`), pool cap (`redis_max_connections`), health-check interval (`redis_health_check_interval`), and — when `redis_retries > 0` — a client-level `Retry` with exponential backoff on connection/timeout errors. Pings to verify connectivity. Raises `GuardRedisError(503)` on failure.

Note that the client-level retry re-sends non-idempotent commands: a lost reply after the server already committed an `INCR` over-counts by one. For guard-core's rate-limit counters that fails closed (mildly over-restrictive, self-heals next window); callers needing exactly-once semantics should not build on `incr()`.

**Close**:

```python
await redis_manager.close()
```

Closes the connection and sets `_closed = True`. Subsequent operations will raise `GuardRedisError`.

### Connection Context Manager

```python
@asynccontextmanager
async def get_connection(self) -> AsyncIterator[Redis]:
```

All operations use this context manager, which:

1. Checks if the connection is closed.
2. Auto-initializes if `_redis` is `None`.
3. Yields the Redis connection.
4. Catches `ConnectionError` and `AttributeError`, wrapping them in `GuardRedisError(503)`.

### Safe Operations

```python
async def safe_operation(self, func, *args, **kwargs) -> Any
```

Wraps any async function that takes a Redis connection as its first argument. Returns `None` if Redis is disabled. Raises `GuardRedisError` on failure.

___

Key Namespacing
---------------

All keys are prefixed with `config.redis_prefix` (default: `"guard_core:"`) and organized by namespace:

```text
{redis_prefix}{namespace}:{key}
```

**Examples**:

| Operation                          | Redis Key                              |
|------------------------------------|----------------------------------------|
| Banned IP lookup                   | `guard_core:banned_ips:192.168.1.1`    |
| Rate limit counter                 | `guard_core:rate_limit:rate:10.0.0.1`  |
| Cloud IP cache                     | `guard_core:cloud_ranges:AWS`          |
| Custom patterns                    | `guard_core:patterns:custom`           |
| Security headers config            | `guard_core:security_headers:csp_config` |
| Behavioral tracking                | `guard_core:behavior_usage:{key}:{ts}` |

### Key Operations

| Method                              | Description                                   |
|-------------------------------------|-----------------------------------------------|
| `get_key(namespace, key)`           | Get a namespaced key value                    |
| `set_key(namespace, key, value, ttl)` | Set with optional TTL (uses `SETEX` if TTL provided) |
| `incr(namespace, key, ttl)`         | Atomic increment with optional TTL            |
| `exists(namespace, key)`            | Check key existence                           |
| `delete(namespace, key)`            | Delete a single key                           |
| `keys(pattern)`                     | Find keys matching a pattern (auto-prefixed)  |
| `delete_pattern(pattern)`           | Delete all keys matching a pattern            |

All methods return `None` when Redis is disabled (`config.enable_redis = False`), allowing callers to fall back to local state without error handling.

___

Fault Tolerance
---------------

### Graceful Degradation

When Redis is unavailable, guard-core falls back to in-memory state for all subsystems:

| Subsystem          | Redis State                    | Fallback                        |
|--------------------|--------------------------------|---------------------------------|
| Rate limiting      | Sorted sets per IP             | In-memory `defaultdict(deque)`  |
| IP banning         | Key-value with TTL             | `TTLCache(maxsize=10000)`       |
| Cloud IP ranges    | Cached CIDR strings            | Direct HTTP fetch + memory      |
| Suspicious patterns| Custom pattern list             | Built-in patterns only          |
| Security headers   | Configuration cache            | In-memory configuration         |

### Error Handling

`GuardRedisError` is raised with a `status_code` and `detail`:

```python
class GuardRedisError(GuardCoreError):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
```

Adapters should catch `GuardRedisError` during initialization and handle it according to their framework's error model.

When a `GuardRedisError` escapes a security check at request time (a Redis outage mid-request), the pipeline honors `fail_secure` by default: the request is blocked with a 500. Setting `redis_fail_open=True` opts into skipping the failing check and letting the request through, treating Redis outages as an availability concern distinct from other check failures.

___

Configuration
-------------

| Field                            | Type           | Default                   | Description                              |
|----------------------------------|----------------|---------------------------|------------------------------------------|
| `enable_redis`                   | `bool`         | `True`                    | Master switch for Redis integration      |
| `redis_url`                      | `str \| None`  | `"redis://localhost:6379"`| Redis connection URL                     |
| `redis_prefix`                   | `str`          | `"guard_core:"`           | Key prefix for namespace isolation       |
| `redis_socket_connect_timeout`   | `float \| None`| `2.0`                     | Seconds to wait establishing a TCP connection (must be positive; `None` disables) |
| `redis_socket_timeout`           | `float \| None`| `2.0`                     | Seconds to wait on a read/write (must be positive; `None` disables) |
| `redis_health_check_interval`    | `int`          | `30`                      | Seconds between pooled-connection health checks (`0` disables) |
| `redis_max_connections`          | `int \| None`  | `None`                    | Connection-pool cap (`None` uses redis-py's default) |
| `redis_retries`                  | `int`          | `1`                       | Client-level retries with exponential backoff (`0` disables) |
| `redis_fail_open`                | `bool`         | `False`                   | On Redis outage, skip the failing check instead of honoring `fail_secure` |

### Adapter Considerations

- Set `redis_prefix` to a unique value per application to avoid key collisions when sharing a Redis instance.
- When `enable_redis` is `False`, all `RedisManager` methods return `None` without attempting connections.
- The `redis_url` can include authentication: `"redis://user:password@host:port/db"`.
