---

title: Handlers
description: API reference for guard-core's handler classes including IPBanManager, RateLimitManager, CloudManager, and others
keywords: handlers, ip ban, rate limit, cloud, redis, security headers, guard-core
---

Handlers
========

Guard-core handlers are singleton services that manage specific security subsystems. Each handler supports optional Redis and agent integration.

___

IPBanManager
------------

Manages banned IP addresses with a dual-layer cache (TTLCache + Redis).

```python
class IPBanManager:
    banned_ips: TTLCache
    redis_handler: Any
    agent_handler: Any

    async def initialize_redis(self, redis_handler: Any) -> None:
        """
        Set the Redis handler for distributed ban storage.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    async def ban_ip(
        self, ip: str, duration: int, reason: str = "threshold_exceeded"
    ) -> None:
        """
        Ban an IP for the given duration in seconds.
        """

    async def unban_ip(self, ip: str) -> None:
        """
        Remove a ban for the given IP.
        """

    async def is_ip_banned(self, ip: str) -> bool:
        """
        Check whether an IP is currently banned.
        """

    async def reset(self) -> None:
        """
        Clear all bans from local cache and Redis.
        """
```

___

RateLimitManager
----------------

Implements sliding window rate limiting with in-memory and Redis backends.

```python
class RateLimitManager:
    config: SecurityConfig
    request_timestamps: defaultdict[str, deque[float]]
    logger: logging.Logger
    redis_handler: Any
    agent_handler: Any
    rate_limit_script_sha: str | None

    def __new__(
        cls: type["RateLimitManager"], config: SecurityConfig
    ) -> "RateLimitManager":
        """
        Singleton constructor. Accepts a SecurityConfig instance.
        """

    async def initialize_redis(self, redis_handler: Any) -> None:
        """
        Set the Redis handler and load the Lua rate-limiting script.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    async def check_rate_limit(
        self,
        request: GuardRequest,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[GuardResponse]],
        endpoint_path: str = "",
        rate_limit: int | None = None,
        rate_limit_window: int | None = None,
    ) -> GuardResponse | None:
        """
        Check whether the client has exceeded the rate limit.
        Returns a 429 response if exceeded, None otherwise.
        """

    async def reset(self) -> None:
        """
        Clear all in-memory timestamps and Redis rate-limit keys.
        """
```

___

CloudManager
------------

Fetches and caches IP ranges for AWS, GCP, and Azure cloud providers.

```python
class CloudManager:
    ip_ranges: dict[str, set[IPv4Network | IPv6Network]]
    last_updated: dict[str, datetime | None]
    redis_handler: Any
    agent_handler: Any
    logger: logging.Logger

    async def initialize_redis(
        self,
        redis_handler: Any,
        providers: set[str] = {"AWS", "GCP", "Azure"},
        ttl: int = 3600,
    ) -> None:
        """
        Set the Redis handler and refresh cloud IP ranges with caching.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    async def refresh(
        self, providers: set[str] = {"AWS", "GCP", "Azure"}
    ) -> None:
        """
        Refresh IP ranges without Redis. Raises RuntimeError if Redis is enabled.
        """

    async def refresh_async(
        self,
        providers: set[str] = {"AWS", "GCP", "Azure"},
        ttl: int = 3600,
    ) -> None:
        """
        Refresh IP ranges with optional Redis caching.
        """

    def is_cloud_ip(
        self, ip: str, providers: set[str] = {"AWS", "GCP", "Azure"}
    ) -> bool:
        """
        Check whether an IP belongs to any of the given cloud providers.
        """

    def get_cloud_provider_details(
        self, ip: str, providers: set[str] = {"AWS", "GCP", "Azure"}
    ) -> tuple[str, str] | None:
        """
        Return (provider, network) for the IP, or None.
        """

    async def send_cloud_detection_event(
        self,
        ip: str,
        provider: str,
        network: str,
        action_taken: str = "request_blocked",
    ) -> None:
        """
        Send a cloud-blocked telemetry event via the agent handler.
        """
```

___

RedisManager
------------

Provides namespaced Redis operations with connection management and fault tolerance.

```python
class RedisManager:
    config: SecurityConfig
    logger: logging.Logger
    agent_handler: Any

    def __new__(
        cls: type["RedisManager"], config: SecurityConfig
    ) -> "RedisManager":
        """
        Constructor. Accepts a SecurityConfig instance.
        """

    async def initialize(self) -> None:
        """
        Establish the Redis connection. Raises GuardRedisError on failure.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    async def close(self) -> None:
        """
        Close the Redis connection gracefully.
        """

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        """
        Context manager yielding a live Redis connection.
        """

    async def safe_operation(
        self, func: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """
        Execute a function with an auto-managed Redis connection.
        """

    async def get_key(self, namespace: str, key: str) -> Any:
        """
        Get a namespaced key value.
        """

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        """
        Set a namespaced key with optional TTL.
        """

    async def incr(
        self, namespace: str, key: str, ttl: int | None = None
    ) -> int | None:
        """
        Atomically increment a namespaced key.
        """

    async def exists(self, namespace: str, key: str) -> bool | None:
        """
        Check whether a namespaced key exists.
        """

    async def delete(self, namespace: str, key: str) -> int | None:
        """
        Delete a namespaced key.
        """

    async def keys(self, pattern: str) -> list[str] | None:
        """
        List keys matching a namespaced pattern.
        """

    async def delete_pattern(self, pattern: str) -> int | None:
        """
        Delete all keys matching a namespaced pattern.
        """
```

___

SecurityHeadersManager
----------------------

Applies HTTP security headers (CSP, HSTS, CORS, and defaults) to responses.

```python
class SecurityHeadersManager:
    headers_cache: TTLCache
    redis_handler: Any
    agent_handler: Any
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, Any] | None
    cors_config: dict[str, Any] | None
    default_headers: dict[str, str]

    async def initialize_redis(self, redis_handler: Any) -> None:
        """
        Set the Redis handler and load/cache header configuration.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    def configure(
        self,
        *,
        enabled: bool = True,
        csp: dict[str, list[str]] | None = None,
        hsts_max_age: int | None = None,
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = False,
        frame_options: str | None = None,
        content_type_options: str | None = None,
        xss_protection: str | None = None,
        referrer_policy: str | None = None,
        permissions_policy: str | None = "UNSET",
        custom_headers: dict[str, str] | None = None,
        cors_origins: list[str] | None = None,
        cors_allow_credentials: bool = False,
        cors_allow_methods: list[str] | None = None,
        cors_allow_headers: list[str] | None = None,
    ) -> None:
        """
        Configure all security header subsystems at once.
        """

    async def get_headers(
        self, request_path: str | None = None
    ) -> dict[str, str]:
        """
        Build and return the full set of security headers for a request path.
        """

    async def get_cors_headers(self, origin: str) -> dict[str, str]:
        """
        Return CORS headers for the given origin, or empty dict if disallowed.
        """

    async def validate_csp_report(
        self, report: dict[str, Any]
    ) -> bool:
        """
        Validate and log a CSP violation report. Returns True if valid.
        """

    async def reset(self) -> None:
        """
        Reset all header configuration and caches.
        """
```

___

BehaviorTracker
---------------

Tracks endpoint usage patterns and response patterns for behavioral analysis.

```python
class BehaviorRule:
    def __init__(
        self,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        threshold: int,
        window: int = 3600,
        pattern: str | None = None,
        action: Literal["ban", "log", "throttle", "alert"] = "log",
        custom_action: Callable | None = None,
    ):
        """
        Define a single behavioral analysis rule.
        """


class BehaviorTracker:
    def __init__(self, config: SecurityConfig):
        """
        Create a tracker bound to the given SecurityConfig.
        """

    async def initialize_redis(self, redis_handler: Any) -> None:
        """
        Set the Redis handler for distributed tracking.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    async def track_endpoint_usage(
        self, endpoint_id: str, client_ip: str, rule: BehaviorRule
    ) -> bool:
        """
        Record a usage event. Returns True if the threshold is exceeded.
        """

    async def track_return_pattern(
        self,
        endpoint_id: str,
        client_ip: str,
        response: GuardResponse,
        rule: BehaviorRule,
    ) -> bool:
        """
        Record a return-pattern match. Returns True if the threshold is exceeded.
        """

    async def apply_action(
        self,
        rule: BehaviorRule,
        client_ip: str,
        endpoint_id: str,
        details: str,
    ) -> None:
        """
        Execute the action defined by the rule (ban, log, throttle, or alert).
        """
```

___

SusPatternsManager
------------------

Orchestrates the detection engine for threat pattern matching and semantic analysis.

```python
class SusPatternsManager:
    patterns: list[str]
    custom_patterns: set[str]
    compiled_patterns: list[tuple[re.Pattern, frozenset[str]]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str]]]
    redis_handler: Any
    agent_handler: Any

    def __new__(
        cls: type["SusPatternsManager"], config: Any = None
    ) -> "SusPatternsManager":
        """
        Singleton constructor. Optionally accepts a config to initialize
        the detection engine components (compiler, preprocessor, semantic
        analyzer, performance monitor).
        """

    async def initialize_redis(self, redis_handler: Any) -> None:
        """
        Set the Redis handler and load cached custom patterns.
        """

    async def initialize_agent(self, agent_handler: Any) -> None:
        """
        Set the agent handler for telemetry events.
        """

    async def detect(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Run full detection (regex + semantic) on content.
        Returns a result dict with is_threat, threat_score, threats, etc.
        """

    async def detect_pattern_match(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Simplified detection returning (is_threat, matched_pattern_or_None).
        """

    @classmethod
    async def add_pattern(
        cls, pattern: str, custom: bool = False
    ) -> None:
        """
        Add a regex pattern to the detection engine.
        """

    @classmethod
    async def remove_pattern(
        cls, pattern: str, custom: bool = False
    ) -> bool:
        """
        Remove a pattern. Returns True if it was found and removed.
        """

    @classmethod
    async def get_default_patterns(cls) -> list[str]: ...

    @classmethod
    async def get_custom_patterns(cls) -> list[str]: ...

    @classmethod
    async def get_all_patterns(cls) -> list[str]: ...

    @classmethod
    async def get_all_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str]]]: ...

    @classmethod
    async def get_performance_stats(cls) -> dict[str, Any] | None:
        """
        Return performance statistics if the monitor is active.
        """

    @classmethod
    async def get_component_status(cls) -> dict[str, bool]:
        """
        Return which detection engine components are active.
        """

    async def configure_semantic_threshold(
        self, threshold: float
    ) -> None:
        """
        Set the semantic detection threshold (clamped to 0.0-1.0).
        """

    @classmethod
    async def reset(cls) -> None:
        """
        Clear custom patterns, handlers, and caches.
        """
```
