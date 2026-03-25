---

title: Rate Limiting
description: RateLimitManager internals, sliding window algorithm, Redis Lua scripts, and per-endpoint rate limits in guard-core
keywords: rate limiting, sliding window, redis, lua script, guard-core
---

Rate Limiting
=============

Guard-core implements rate limiting using a sliding window algorithm with dual backends: in-memory for single-instance deployments and Redis for distributed deployments. The `RateLimitManager` handler orchestrates both.

RateLimitManager
----------------

### Singleton Pattern

`RateLimitManager` is a singleton parameterized by `SecurityConfig`:

```python
class RateLimitManager:
    _instance: Optional["RateLimitManager"] = None

    def __new__(cls, config: SecurityConfig) -> "RateLimitManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.request_timestamps = defaultdict(deque)
            cls._instance.rate_limit_script_sha = None
        cls._instance.config = config
        return cls._instance
```

The config is always updated on access, allowing runtime reconfiguration.

### Core Method

```python
async def check_rate_limit(
    self,
    request: GuardRequest,
    client_ip: str,
    create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
    endpoint_path: str = "",
    rate_limit: int | None = None,
    rate_limit_window: int | None = None,
) -> GuardResponse | None
```

**Parameters**:

| Parameter             | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `request`             | The current request object                                    |
| `client_ip`           | Resolved client IP address                                    |
| `create_error_response` | Factory callback for creating error responses               |
| `endpoint_path`       | Optional path for per-endpoint tracking                       |
| `rate_limit`          | Override for `config.rate_limit`                              |
| `rate_limit_window`   | Override for `config.rate_limit_window`                       |

**Returns**: `None` if under the limit, or a `429` response if exceeded.

___

Sliding Window Algorithm
------------------------

### In-Memory Backend

Uses `collections.defaultdict[str, deque[float]]` keyed by `"{client_ip}:{endpoint_path}"` or just `"{client_ip}"` for global limits.

```python
def _get_in_memory_request_count(
    self, client_ip, window_start, current_time, endpoint_path=""
) -> int:
    key = f"{client_ip}:{endpoint_path}" if endpoint_path else client_ip
    while self.request_timestamps[key] and self.request_timestamps[key][0] <= window_start:
        self.request_timestamps[key].popleft()
    request_count = len(self.request_timestamps[key])
    self.request_timestamps[key].append(current_time)
    return request_count
```

The deque acts as a sliding window. Timestamps older than `current_time - window` are evicted on each call.

### Redis Backend

Uses a Redis sorted set where:

- **Key**: `{redis_prefix}rate_limit:rate:{client_ip}:{endpoint_path}`
- **Members**: Timestamps (as strings)
- **Scores**: Timestamps (as floats)

Each request:

1. Adds the current timestamp (`ZADD`).
2. Removes all entries before the window start (`ZREMRANGEBYSCORE`).
3. Counts remaining entries (`ZCARD`).
4. Sets a TTL of `window * 2` to prevent key leakage.

___

Lua Script for Atomic Operations
---------------------------------

When Redis is available, guard-core loads a Lua script at initialization for atomic rate limit operations:

```lua
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
local count = redis.call('ZCARD', key)
redis.call('EXPIRE', key, window * 2)

return count
```

The script SHA is cached in `rate_limit_script_sha` and executed with `EVALSHA` on each request.

**Advantages of the Lua approach**:

- **Atomicity**: All four operations execute as a single Redis transaction.
- **Performance**: One round trip instead of four.
- **Consistency**: No race conditions between concurrent requests.

### Fallback

If the Lua script is not loaded (e.g., script load failed), the Redis backend falls back to a pipeline of individual commands:

```python
pipeline = conn.pipeline()
pipeline.zadd(key_name, {str(current_time): current_time})
pipeline.zremrangebyscore(key_name, 0, window_start)
pipeline.zcard(key_name)
pipeline.expire(key_name, window * 2)
results = await pipeline.execute()
```

If Redis fails entirely (connection error), the system falls back to in-memory rate limiting with a log warning.

___

Per-Endpoint Rate Limits
------------------------

The `RateLimitCheck` pipeline check evaluates rate limits in priority order:

| Priority | Source                               | Configuration                                    |
|----------|--------------------------------------|--------------------------------------------------|
| 1        | Dynamic endpoint rules               | `config.endpoint_rate_limits[path] = (limit, window)` |
| 2        | Route decorator                      | `RouteConfig.rate_limit` + `RouteConfig.rate_limit_window` |
| 3        | Geo-based route limits               | `RouteConfig.geo_rate_limits[country] = (limit, window)` |
| 4        | Global                               | `config.rate_limit` + `config.rate_limit_window` |

The first matching tier short-circuits evaluation. For endpoint-specific and route-level limits, the `endpoint_path` parameter is set so that the rate counters are tracked separately from global counters.

### Geo-Based Rate Limits

When `RouteConfig.geo_rate_limits` is configured, the check resolves the client's country via `GeoIPHandler`, then looks up the limit:

1. Exact country match (e.g., `"US"`).
2. Wildcard fallback (`"*"`).
3. If no match, skips to the next tier.

___

Initialization
--------------

```python
rate_limit_manager = RateLimitManager(config)
await rate_limit_manager.initialize_redis(redis_handler)
await rate_limit_manager.initialize_agent(agent_handler)
```

Redis initialization triggers the Lua script load. If it fails, the manager logs an error and proceeds with the pipeline fallback.

___

Reset
-----

```python
await rate_limit_manager.reset()
```

Clears the in-memory `request_timestamps` dictionary and deletes all `rate_limit:rate:*` keys from Redis.
