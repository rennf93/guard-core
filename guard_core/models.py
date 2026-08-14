import difflib
import logging
import warnings
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from guard_core import __version__
from guard_core._security_config_validators import (
    _FIELD_REVALIDATORS,
    _GEO_STATE_FIELDS,
    _GLOBAL_BEHAVIOR_RULE_FIELDS,
    BehaviorRuleConfig,
    ThreatBanConfig,
    _apply_geo_ip_handler_assignment,
    _country_shadow_should_warn,
    _extra_installed,
    _resolve_geo_ip_handler,
    _revalidate_copied_config,
    _validate_block_cloud_providers_value,
    _validate_enabled_detection_categories_value,
    _validate_exclude_paths_value,
    _validate_global_behavior_rule_assignment,
    _validate_ip_or_cidr_list,
    _validate_muted_check_logs_value,
    _validate_muted_event_types_value,
    _validate_muted_metric_types_value,
    _validate_return_pattern_body_scan,
    _validate_threat_ban_config_value,
    _warn_country_allowlist_shadows_blocklist,
    cloud_blocking_enabled,
)
from guard_core._security_config_validators import (
    VALID_CLOUD_PROVIDERS as VALID_CLOUD_PROVIDERS,
)
from guard_core._security_config_validators import CloudProvider as CloudProvider
from guard_core._security_config_validators import (
    return_pattern_requires_response_body as return_pattern_requires_response_body,
)
from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES
from guard_core.protocols.cloud_ip_store_protocol import (
    CloudIpStoreFactory,
    CloudIpStoreProtocol,
)
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse

if TYPE_CHECKING:
    from guard_agent import AgentConfig


logger = logging.getLogger("guard_core.models")


class SecurityConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    _revision: int = PrivateAttr(default=0)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "exclude_paths":
            value = _validate_exclude_paths_value(value, stacklevel=3)
        if name in _GLOBAL_BEHAVIOR_RULE_FIELDS:
            _validate_global_behavior_rule_assignment(self, name, value)
        if name in _GEO_STATE_FIELDS:
            value = _apply_geo_ip_handler_assignment(self, name, value)
        if name in _FIELD_REVALIDATORS:
            value = _FIELD_REVALIDATORS[name](value)

        should_warn = _country_shadow_should_warn(self, name, value)

        super().__setattr__(name, value)
        if name != "_revision":
            object.__setattr__(self, "_revision", self._revision + 1)
        if should_warn:
            _warn_country_allowlist_shadows_blocklist(stacklevel=3)

    @property
    def revision(self) -> int:
        return self._revision

    def model_copy(
        self, *, update: Mapping[str, Any] | None = None, deep: bool = False
    ) -> Self:
        copied = super().model_copy(update=update, deep=deep)
        if update:
            _revalidate_copied_config(copied, update)
        return copied

    trusted_proxies: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Trusted proxy IPs or CIDR ranges for X-Forwarded-For",
    )

    trusted_proxy_depth: int = Field(
        default=1,
        description="How many proxies to expect in the X-Forwarded-For chain",
    )

    trust_x_forwarded_proto: bool = Field(
        default=False,
        description="Trust X-Forwarded-Proto header for HTTPS detection",
    )

    passive_mode: bool = Field(
        default=False,
        description="Enable Log-Only mode. Won't block requests, only log.",
    )

    geo_ip_handler: GeoIPHandler | None = Field(
        default=None,
        description="Geographical IP handler to use for IP geolocation",
    )

    enable_redis: bool = Field(
        default=True,
        description="Enable/disable Redis for distributed state management",
    )

    redis_url: str | None = Field(
        default="redis://localhost:6379",
        description="Redis URL for distributed state management",
    )

    redis_prefix: str = Field(
        default="guard_core:",
        description="Prefix for Redis keys to avoid collisions with other apps",
    )

    redis_socket_connect_timeout: float | None = Field(
        default=2.0,
        gt=0.0,
        description=(
            "Seconds to wait establishing a Redis TCP connection before giving up. "
            "Must be positive: 0 would put the socket in non-blocking mode, not "
            "disable the timeout. None disables the timeout (a partitioned/"
            "black-holed Redis then blocks the request indefinitely), so a bounded "
            "default is strongly recommended."
        ),
    )

    redis_socket_timeout: float | None = Field(
        default=2.0,
        gt=0.0,
        description=(
            "Seconds to wait on a Redis read/write before raising. Must be "
            "positive: 0 would put the socket in non-blocking mode, not disable "
            "the timeout. None means no timeout. Keep this low: every blocked "
            "Redis call blocks a request."
        ),
    )

    redis_health_check_interval: int = Field(
        default=30,
        ge=0,
        description=(
            "Seconds between health checks on pooled connections; recycles stale "
            "sockets so the first request after an idle period doesn't fail. "
            "0 disables health checks."
        ),
    )

    redis_max_connections: int | None = Field(
        default=None,
        ge=1,
        description=(
            "Cap on the Redis connection pool size. None uses redis-py's default."
        ),
    )

    redis_retries: int = Field(
        default=1,
        ge=0,
        description=(
            "Number of retries (with exponential backoff) on transient Redis "
            "connection/timeout errors before surfacing it. 0 disables retries."
        ),
    )

    whitelist: tuple[str, ...] | None = Field(
        default=None,
        description=(
            "Allowed IP addresses or CIDR ranges. A non-empty whitelist is "
            "restrictive: only listed IPs pass the global IP check. An explicit "
            "whitelist match overrides the blacklist; dynamic IP bans still apply."
        ),
    )

    blacklist: tuple[str, ...] = Field(
        default_factory=tuple,
        description=(
            "Blocked IP addresses or CIDR ranges. Enforced ahead of country and "
            "cloud-provider checks, but overridden by an explicit whitelist match."
        ),
    )

    whitelist_countries: frozenset[str] = Field(
        default_factory=frozenset,
        description=(
            "Allowed country codes (ISO 3166-1 alpha-2). A non-empty set is "
            "restrictive: only listed countries pass the global country check, "
            "and an unresolved country is blocked. An explicit match overrides "
            "blocked_countries."
        ),
    )

    blocked_countries: frozenset[str] = Field(
        default_factory=frozenset,
        description="Country codes that are always blocked",
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="Blocked user agents"
    )

    auto_ban_threshold: int = Field(
        default=10, description="Number of suspicious requests before auto-ban"
    )

    auto_ban_duration: int = Field(
        default=3600, description="Duration of auto-ban in seconds (default: 1 hour)"
    )

    threat_ban_config: MappingProxyType[str, ThreatBanConfig] = Field(
        default_factory=lambda: MappingProxyType({}),
        description=(
            "Per-category ban thresholds and durations. "
            "Unlisted categories fall back to auto_ban_threshold / auto_ban_duration."
        ),
    )

    global_behavior_rules: tuple[BehaviorRuleConfig, ...] = Field(
        default_factory=tuple,
        description=(
            "Behaviour rules applied to every route, in addition to any "
            "decorator-specified rules. Useful for global 404 tracking."
        ),
    )

    behavior_scan_response_body: bool = Field(
        default=False,
        description=(
            "Read response bodies to evaluate return_pattern behaviour rules "
            "whose pattern is not a status: pattern (json:, regex:, or a bare "
            "substring). Default off: with this False, no response body is "
            "ever read for pattern matching, and such rules never match -- "
            "construction rejects one instead of accepting a rule that would "
            "silently no-op (see the return_pattern validator below). "
            "status: patterns match on status_code alone and are unaffected "
            "by this flag. Because the response body is application-produced "
            "rather than attacker-supplied, enabling this on an endpoint that "
            "streams large responses (a file download, an export, an SSE "
            "stream) means every response through that endpoint is now read "
            "up to behavior_max_response_body_inspect_bytes on every request; "
            "size the cap and pick routes accordingly."
        ),
    )

    behavior_max_response_body_inspect_bytes: int = Field(
        default=262144,
        description=(
            "Maximum bytes read from the start of a response body and held "
            "for return_pattern inspection when behavior_scan_response_body "
            "is True. This bounds what guard-core retains, not what the "
            "application produces: an adapter's BoundedResponseBodyReader "
            "implementation must buffer at most this many bytes internally "
            "and must still deliver the response's full, unbounded body to "
            "the client afterward -- a streaming response stays streaming. "
            "Only this leading prefix is ever scanned; a payload placed "
            "after it, or a signature split across the boundary, is not "
            "detected. That tradeoff is inherent to bounded-memory scanning. "
            "Distinct from detection_max_body_inspect_bytes, which bounds "
            "request bodies for penetration detection, not response bodies "
            "for behaviour rules."
        ),
        ge=1024,
        le=10485760,
    )

    body_read_timeout: float = Field(
        default=3.0,
        description=(
            "Seconds to wait for an adapter's read_body_prefix or body call "
            "before giving up. Applies to both the ASYNC guard_core tree "
            "(guard_core.utils, guard_core.handlers.behavior_handler), where "
            "it bounds the read via asyncio.wait_for, and the SYNC tree "
            "(guard_core.sync), where a blocking call cannot be cancelled "
            "from the outside, so each read attempt instead runs on its own "
            "daemon thread and this value bounds how long the caller joins "
            "that thread (see sync_body_read_max_concurrent for the thread "
            "budget). In both trees it bounds the request-body detection "
            "read and the response-body behaviour-rule read against a "
            "stalled or misbehaving adapter/stream (a stalled SSE producer, "
            "a long-poll that never yields, a buggy implementation); on "
            "timeout the body is treated as unavailable, the same "
            "fail-closed outcome already used when the adapter raises. The "
            "sync tree's timed-out thread keeps running in the background "
            "until the adapter's call itself returns; only the caller stops "
            "waiting for it."
        ),
        gt=0.0,
        le=30.0,
    )

    sync_body_read_max_concurrent: int = Field(
        default=64,
        description=(
            "Maximum number of daemon threads the SYNC guard_core tree may "
            "have blocked at once inside an adapter's read_body_prefix or "
            "body call. A blocking sync read cannot be cancelled, so each "
            "attempt runs on its own daemon thread and waits up to "
            "body_read_timeout for it; once this many threads are already "
            "blocked on a stalled read, further attempts queue for the same "
            "budget and then give up and log the exhaustion, keeping the "
            "thread count bounded instead of growing without limit."
        ),
        ge=1,
        le=10000,
    )

    custom_log_file: str | None = Field(
        default=None,
        description="The path to a custom log file for logging security events",
    )

    log_suspicious_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default="WARNING", description="Log level for suspicious requests")

    log_request_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default=None, description="Log level for requests")

    log_country_check_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(
        default="INFO",
        description=(
            "Log level for per-request country verdicts that are not blocks "
            "(whitelisted / not-affected). Set to None to silence them. "
            "Blocked-country hits log at log_suspicious_level instead; "
            "no-rules and no-geolocation cases always log at DEBUG."
        ),
    )

    log_format: Literal["text", "json"] = Field(
        default="text",
        description="Log output format: 'text' or 'json' for structured JSON",
    )

    custom_error_responses: dict[int, str] = Field(
        default_factory=dict, description="Custom error for specific HTTP status codes"
    )

    rate_limit: int = Field(
        default=10, description="Maximum requests per rate_limit_window"
    )

    rate_limit_window: int = Field(
        default=60, description="Rate limiting time window (seconds)"
    )

    enforce_https: bool = Field(
        default=False, description="Whether to enforce HTTPS connections"
    )

    security_headers: dict[str, Any] | None = Field(
        default_factory=lambda: {
            "enabled": True,
            "hsts": {
                "max_age": 31536000,
                "include_subdomains": True,
                "preload": False,
            },
            "csp": None,
            "frame_options": "SAMEORIGIN",
            "content_type_options": "nosniff",
            "xss_protection": "1; mode=block",
            "referrer_policy": "strict-origin-when-cross-origin",
            "permissions_policy": "geolocation=(), microphone=(), camera=()",
            "custom": None,
        },
        description="Security headers configuration",
    )

    custom_request_check: (
        Callable[[GuardRequest], Awaitable[GuardResponse | None]] | None
    ) = Field(default=None, description="Perform additional checks on the request")

    custom_response_modifier: (
        Callable[[GuardResponse], Awaitable[GuardResponse]] | None
    ) = Field(
        default=None,
        description="A custom function to modify the response before it's sent",
    )

    enable_cors: bool = Field(default=False, description="Enable/disable CORS")

    cors_allow_origins: list[str] = Field(
        default_factory=lambda: ["*"], description="Origins allowed in CORS requests"
    )

    cors_allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        description="Methods allowed in CORS requests",
    )

    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["*"], description="Headers allowed in CORS requests"
    )

    cors_allow_credentials: bool = Field(
        default=False, description="Whether to allow credentials in CORS requests"
    )

    cors_expose_headers: list[str] = Field(
        default_factory=list, description="Headers exposed in CORS responses"
    )

    cors_max_age: int = Field(
        default=600, description="Maximum age of CORS preflight results"
    )

    block_cloud_providers: frozenset[str] | None = Field(
        default=None,
        description=(
            "Cloud providers to block: AWS, GCP, Azure, DigitalOcean, Linode, "
            "Vultr. A bare provider ('GCP') blocks the whole provider; a region "
            "carve-out ('GCP:!us-central1') blocks the provider except that "
            "region. Region metadata exists for AWS, GCP and Azure; the other "
            "providers publish no region data, so a carve-out on them exempts "
            "nothing and the whole provider stays blocked. An unrecognized "
            "provider name raises ValueError rather than being silently dropped."
        ),
    )

    cloud_ip_refresh_interval: int = Field(
        default=3600,
        description="Interval in seconds between cloud IP range refreshes",
        ge=60,
        le=86400,
    )

    lazy_init: bool = Field(
        default=True,
        description=(
            "When True (default), guard-core defers cloud-IP HTTP fetches and "
            "geo-IP MMDB downloads to a background task, so the application does "
            "not block on multi-second network calls. This only takes effect when "
            "Redis is enabled (enable_redis=True and a redis_handler is wired) "
            "and the consuming adapter calls initialize_redis_handlers() during "
            "its own opt-in startup hook (for example fastapi-guard's lifespan "
            "integration) — it is not triggered by app boot on its own. Without "
            "Redis, or without that hook wired, cloud/geo initialization instead "
            "happens through their on-demand paths and this flag has no effect. "
            "First requests may see partially-populated cloud-IP ranges until "
            "the background task completes (typically 1-3 seconds). "
            "Set to False only if you require synchronous-init guarantees and "
            "are willing to block app startup until all initial network calls finish."
        ),
    )

    geo_ip_db_max_age: int = Field(
        default=86400,
        ge=3600,
        le=604800,
        description="Maximum age in seconds for the IPInfo MMDB before re-download.",
    )

    cloud_ip_store: CloudIpStoreProtocol | CloudIpStoreFactory | None = Field(
        default=None,
        description=(
            "Override the default cloud IP store. Accepts either an instance "
            "implementing CloudIpStoreProtocol, or a callable that takes the "
            "Redis handler and returns a store (used to defer construction "
            "until the redis_handler is available). When None (default), "
            "guard-core auto-constructs a RedisCloudIpStore if Redis is enabled."
        ),
    )

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/openapi.yaml",
            "/favicon.ico",
            "/static",
        ],
        description="Paths to exclude from security checks",
    )

    enable_ip_banning: bool = Field(
        default=True, description="Enable/disable IP banning functionality"
    )

    enable_rate_limiting: bool = Field(
        default=True, description="Enable/disable rate limiting functionality"
    )

    enable_penetration_detection: bool = Field(
        default=True, description="Enable/disable penetration attempt detection"
    )

    fail_secure: bool = Field(
        default=True,
        description=(
            "Block the request when any security check raises an unexpected exception. "
            "True (default) returns HTTP 500 so check bugs surface; "
            "False logs and falls through (fail-open) - "
            "opt-in only for staging diagnostics."
        ),
    )

    redis_fail_open: bool = Field(
        default=False,
        description=(
            "On GuardRedisError (Redis unreachable), skip the failing check "
            "and let the request through instead of honoring fail_secure. "
            "Defaults to False so fail_secure is the single source of truth "
            "for every check failure, including Redis outages. Set True to "
            "opt into treating Redis outages as an availability concern "
            "distinct from other check failures."
        ),
    )

    route_resolution_strict: bool = Field(
        default=False,
        description=(
            "Block the request when the adapter reports that it could not "
            "resolve the route, instead of running the pipeline with no "
            "per-route config. A missing route config normally means the route "
            "carries no decorators, so the default (False) preserves that and "
            "lets undecorated routes and unrouted requests through. Set True "
            "when every request must be attributable to a known route, so a "
            "resolution failure cannot silently skip per-route checks - note "
            "that this also turns requests to paths the app does not serve "
            "into 500s instead of 404s."
        ),
    )

    ipinfo_token: str | None = Field(
        default=None,
        description="IPInfo API token for IP geolocation. Deprecated. "
        "Create a custom `geo_ip_handler` instead.",
    )

    ipinfo_db_path: Path | None = Field(
        default=Path("data/ipinfo/country_asn.mmdb"),
        description="Path to the IPInfo database file. Deprecated. "
        "Create a custom `geo_ip_handler` instead.",
    )

    enable_agent: bool = Field(
        default=False, description="Enable Guard Agent telemetry and monitoring"
    )

    agent_api_key: str | None = Field(
        default=None, description="API key for Guard Agent SaaS platform"
    )

    agent_strict: bool = Field(
        default=False,
        description=(
            "When True, an enabled agent that cannot be initialized (package "
            "missing or construction failure) raises at middleware init instead "
            "of degrading to agent-off."
        ),
    )

    on_error: Callable[[str, BaseException, dict[str, Any]], None] | None = Field(
        default=None,
        description=(
            "Optional best-effort callback invoked when a middleware/agent step "
            "fails, receiving (stage, exception, context). stage is one of "
            "'agent_init', 'geoip', 'transport_send', 'encryption'. A callback "
            "that raises is caught and logged, never propagated."
        ),
    )

    agent_endpoint: str = Field(
        default="https://api.guard-core.com",
        description="Guard Agent SaaS platform endpoint",
    )

    agent_project_id: str | None = Field(
        default=None, description="Project ID for organizing telemetry data"
    )

    agent_buffer_size: int = Field(
        default=100, description="Number of events to buffer before auto-flush"
    )

    agent_flush_interval: int = Field(
        default=30, description="Interval in seconds between automatic buffer flushes"
    )

    agent_enable_events: bool = Field(
        default=True, description="Enable sending security events to SaaS platform"
    )

    agent_enable_metrics: bool = Field(
        default=True, description="Enable sending performance metrics to SaaS platform"
    )

    agent_timeout: int = Field(
        default=30, description="Timeout in seconds for agent HTTP requests"
    )

    agent_retry_attempts: int = Field(
        default=3, description="Number of retry attempts for failed requests"
    )

    agent_project_encryption_key: str | None = Field(
        default=None,
        description=(
            "Per-project AES-256-GCM key used to encrypt the telemetry payload "
            "between the agent and the SaaS. When set, the agent posts to "
            "/api/v1/events/encrypted instead of /api/v1/events. Required for "
            "API keys that have encryption enforced server-side."
        ),
    )

    agent_guard_version: str | None = Field(
        default=None,
        description=(
            "Framework wrapper version (e.g. fastapi-guard's __version__) "
            "propagated to the agent so the SaaS can attribute telemetry to "
            "the wrapper version, not just the agent version. Set this to "
            "your framework integration's __version__ at construction time."
        ),
    )

    agent_high_watermark_ratio: float | None = Field(
        default=None,
        description=(
            "Buffer occupancy ratio that triggers an early flush. "
            "None defers to the agent's own default."
        ),
    )

    agent_max_concurrent_flushes: int | None = Field(
        default=None,
        description=(
            "Maximum concurrent early-flush operations. "
            "None defers to the agent's own default."
        ),
    )

    agent_buffer_overflow_policy: Literal["drop", "block", "raise"] | None = Field(
        default=None,
        description=(
            "Behavior when the agent's in-memory buffer is full. 'drop' "
            "silently evicts the oldest entry, 'block' awaits free space and "
            "backpressures the caller, 'raise' throws BufferFullError so "
            "callers can react. None defers to the agent's own default "
            "('drop')."
        ),
    )

    agent_backoff_factor: float | None = Field(
        default=None,
        description=(
            "Backoff factor for agent HTTP retries. "
            "None defers to the agent's own default."
        ),
    )

    agent_sensitive_headers: list[str] | None = Field(
        default=None,
        description=(
            "Header names excluded from telemetry payloads. "
            "None defers to the agent's own default."
        ),
    )

    agent_max_payload_size: int | None = Field(
        default=None,
        description=(
            "Maximum payload size in bytes to include in telemetry events. "
            "None defers to the agent's own default."
        ),
    )

    agent_compression_enabled: bool | None = Field(
        default=None,
        description=(
            "Gzip-compress outgoing telemetry batch bodies above "
            "agent_compression_threshold bytes. "
            "None defers to the agent's own default."
        ),
    )

    agent_compression_threshold: int | None = Field(
        default=None,
        description=(
            "Minimum body size in bytes before gzip compression applies. "
            "None defers to the agent's own default."
        ),
    )

    agent_install_id: str | None = Field(
        default=None,
        description=(
            "Override the agent install ID. "
            "None auto-generates one, the agent's own default."
        ),
    )

    agent_payload_signing_secret: str | None = Field(
        default=None,
        description="HMAC-SHA256 secret used to sign the X-Payload-Signature header.",
    )

    enable_dynamic_rules: bool = Field(
        default=False, description="Enable dynamic rule updates from SaaS platform"
    )

    dynamic_rule_interval: int = Field(
        default=300,
        ge=60,
        description="Interval in seconds between dynamic rule updates",
    )

    agent_status_interval: int = Field(
        default=300,
        ge=60,
        le=86400,
        description="Interval in seconds between agent status reports to the SaaS",
    )

    emergency_mode: bool = Field(
        default=False, description="Emergency lockdown mode (set by dynamic rules)"
    )

    emergency_whitelist: list[str] = Field(
        default_factory=list,
        description="Emergency whitelist IPs (set by dynamic rules)",
    )

    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description="Per-endpoint rate limits set by dynamic rules",
    )

    detection_compiler_timeout: float = Field(
        default=2.0,
        description="Timeout for pattern compilation and matching (seconds)",
        ge=0.1,
        le=10.0,
    )

    detection_max_content_length: int = Field(
        default=10000,
        description="Maximum content length for pattern detection",
        ge=1000,
        le=100000,
    )

    detection_max_body_inspect_bytes: int = Field(
        default=262144,
        description=(
            "Maximum bytes read from the start of the request body and inspected "
            "for penetration detection. When the request's Content-Length exceeds "
            "this, the body is not read or scanned and the request proceeds, "
            "bounding memory on the detection hot path. This is a memory bound, "
            "not full-body coverage: only this leading prefix is ever scanned, so "
            "a payload placed after the first N bytes, or a signature split across "
            "the boundary, is not detected. That tradeoff is inherent to "
            "bounded-memory scanning and cannot be closed without reading the "
            "whole body; raise the cap to shrink the blind spot, at the cost of "
            "more memory held per inspected request. Distinct from "
            "detection_max_content_length (the regex scan window) and "
            "max_request_size (the 413 size gate)."
        ),
        ge=1024,
        le=10485760,
    )

    detection_preserve_attack_patterns: bool = Field(
        default=True,
        description="Preserve attack patterns during content truncation",
    )

    detection_semantic_threshold: float = Field(
        default=0.7,
        description="Threshold for semantic attack detection (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )

    detection_anomaly_threshold: float = Field(
        default=3.0,
        description="Standard deviations from mean to consider anomaly",
        ge=1.0,
        le=10.0,
    )

    detection_slow_pattern_threshold: float = Field(
        default=0.1,
        description="Execution time to consider pattern slow (seconds)",
        ge=0.01,
        le=1.0,
    )

    detection_monitor_history_size: int = Field(
        default=1000,
        description="Number of recent metrics to keep in history",
        ge=100,
        le=10000,
    )

    detection_max_tracked_patterns: int = Field(
        default=1000,
        description="Maximum number of patterns to track for performance",
        ge=100,
        le=5000,
    )

    detection_anomaly_emission_cooldown: float = Field(
        default=60.0,
        description=(
            "Min seconds between anomaly events for the same pattern. "
            "Raise to reduce noise on low-traffic apps."
        ),
        ge=1.0,
        le=3600.0,
    )

    detection_min_samples_for_anomaly: int = Field(
        default=30,
        description=(
            "Minimum samples recorded for a pattern before statistical-anomaly "
            "detection engages. Raise to reduce false fires on low-traffic apps."
        ),
        ge=10,
        le=1000,
    )

    detection_threat_score_threshold: float = Field(
        default=1.0,
        description="Anomaly score required to flag a request as a threat",
        ge=0.0,
        le=10.0,
    )

    muted_event_types: frozenset[str] = Field(
        default_factory=frozenset,
        description="Event types to mute from telemetry dispatch",
    )

    muted_metric_types: frozenset[str] = Field(
        default_factory=frozenset,
        description="Metric types to mute from telemetry dispatch",
    )

    muted_check_logs: frozenset[str] = Field(
        default_factory=frozenset,
        description="Security check names to mute from pipeline logging",
    )

    enable_otel: bool = Field(
        default=False,
        description="Enable OpenTelemetry span/metric export (requires [otel] extra)",
    )

    otel_service_name: str = Field(
        default="guard-core",
        description="Service name for OpenTelemetry resource",
    )

    otel_exporter_endpoint: str | None = Field(
        default=None,
        description="OTLP HTTP endpoint for OpenTelemetry export",
    )

    otel_resource_attributes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Additional OpenTelemetry resource attributes "
            "(e.g. deployment.environment, service.version)."
        ),
    )

    enable_logfire: bool = Field(
        default=False,
        description="Enable Logfire span/metric export (requires [logfire] extra)",
    )

    logfire_service_name: str = Field(
        default="guard-core",
        description="Service name for Logfire integration",
    )

    enable_enrichment: bool = Field(
        default=False,
        description=(
            "Populate guard.* metadata on every event and every metric with "
            "project identity, deterministic threat score, matched dynamic "
            "rule, and per-IP behavioral correlation keys. Requires "
            "enable_agent=True — enrichment is the guard-agent-gated tier "
            "of the telemetry pipeline."
        ),
    )

    excluded_detection_headers: set[str] = Field(
        default_factory=set,
        description=(
            "Headers to exclude from penetration detection scanning. "
            "Merged with the hardcoded default exclusion set."
        ),
    )
    excluded_detection_params: set[str] = Field(
        default_factory=set,
        description=(
            "Query parameters to exclude from penetration detection scanning."
        ),
    )
    excluded_detection_body_fields: set[str] = Field(
        default_factory=set,
        description=(
            "JSON body keys to exclude from penetration detection scanning. "
            "Matched at any nesting depth, and applied to x-www-form-urlencoded "
            "and multipart text-part field names as well."
        ),
    )
    detection_scan_body: bool = Field(
        default=True,
        description=(
            "Scan the request body during penetration detection. Set False to "
            "restrict detection to the URL path, query params, and headers; the "
            "body is then never read or matched, regardless of its shape."
        ),
    )
    enabled_detection_categories: frozenset[str] = Field(
        default_factory=lambda: frozenset(ALL_DETECTION_CATEGORIES),
        description=(
            "Detection categories to scan for. Defaults to all. "
            f"Valid values: {sorted(ALL_DETECTION_CATEGORIES)}"
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def warn_unknown_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        known = set(cls.model_fields)
        known.update(field.alias for field in cls.model_fields.values() if field.alias)

        unknown = set(data) - known
        for key in sorted(unknown):
            match = difflib.get_close_matches(str(key), known, n=1)
            hint = f" Did you mean '{match[0]}'?" if match else ""
            logger.warning(
                "SecurityConfig received unknown field '%s'; it was ignored "
                "and had no effect.%s",
                key,
                hint,
            )
        return data

    @field_validator("whitelist", "blacklist", mode="before")
    def validate_ip_lists(cls, v: Any) -> Any:
        return _validate_ip_or_cidr_list(v, invalid_message="Invalid IP or CIDR range")

    @field_validator("trusted_proxies", mode="before")
    def validate_trusted_proxies(cls, v: Any) -> Any:
        return _validate_ip_or_cidr_list(
            v, invalid_message="Invalid proxy IP or CIDR range"
        )

    @field_validator("trusted_proxy_depth")
    def validate_proxy_depth(cls, v: int) -> int:
        if v < 1:
            raise ValueError("trusted_proxy_depth must be at least 1")
        return v

    @field_validator("whitelist_countries", "blocked_countries", mode="before")
    def coerce_country_set(cls, v: Any) -> frozenset[str]:
        if v is None:
            return frozenset()
        if isinstance(v, list | tuple | set | frozenset):
            return frozenset(str(item).upper() for item in v)
        raise ValueError(
            "Country list must be list/tuple/set/frozenset of country codes"
        )

    @field_validator("block_cloud_providers", mode="before")
    def validate_cloud_providers(cls, v: Any) -> frozenset[str]:
        return _validate_block_cloud_providers_value(v)

    @model_validator(mode="after")
    def validate_optional_extras_installed(self) -> Self:
        if self.enable_redis and not _extra_installed("redis"):
            raise ValueError(
                "enable_redis=True requires the 'redis' package. "
                "Install it with: pip install guard-core[redis]"
            )

        if cloud_blocking_enabled(self) and not _extra_installed("aiohttp", "requests"):
            raise ValueError(
                "block_cloud_providers / enable_dynamic_rules requires 'aiohttp' or "
                "'requests'. Install it with: pip install guard-core[cloud]"
            )

        has_country_rules = bool(self.blocked_countries or self.whitelist_countries)
        needs_builtin_geo_handler = self.geo_ip_handler is None and has_country_rules
        if needs_builtin_geo_handler and not _extra_installed("maxminddb"):
            raise ValueError(
                "geo_ip_handler / country rules require the 'maxminddb' package. "
                "Install it with: pip install guard-core[geo]"
            )

        return self

    @model_validator(mode="after")
    def validate_geo_ip_handler_exists(self) -> Self:
        resolved = _resolve_geo_ip_handler(
            blocked_countries=self.blocked_countries,
            whitelist_countries=self.whitelist_countries,
            geo_ip_handler=self.geo_ip_handler,
            ipinfo_token=self.ipinfo_token,
            ipinfo_db_path=self.ipinfo_db_path,
            geo_ip_db_max_age=self.geo_ip_db_max_age,
        )
        if resolved is not self.geo_ip_handler:
            self.geo_ip_handler = resolved

        return self

    @model_validator(mode="after")
    def warn_country_allowlist_shadows_blocklist(self) -> Self:
        if self.whitelist_countries and self.blocked_countries:
            _warn_country_allowlist_shadows_blocklist(stacklevel=4)
        return self

    @model_validator(mode="after")
    def validate_agent_config(self) -> Self:
        if self.enable_agent and not self.agent_api_key:
            raise ValueError("agent_api_key is required when enable_agent is True")

        if self.enable_dynamic_rules and not self.enable_agent:
            raise ValueError(
                "enable_agent must be True when enable_dynamic_rules is True"
            )

        if self.enable_enrichment and not self.enable_agent:
            raise ValueError(
                "enable_enrichment requires enable_agent=True; enrichment is "
                "the guard-agent-gated tier. Either enable guard-agent or set "
                "enable_enrichment=False."
            )

        return self

    @model_validator(mode="after")
    def validate_global_return_pattern_body_scan(self) -> Self:
        for rule in self.global_behavior_rules:
            if rule.rule_type != "return_pattern" or not rule.pattern:
                continue
            _validate_return_pattern_body_scan(rule.pattern, self)
        return self

    @model_validator(mode="after")
    def warn_deprecated_fields(self) -> Self:
        for name in sorted({"ipinfo_token", "ipinfo_db_path"} & self.model_fields_set):
            if getattr(self, name) is None:
                continue
            warnings.warn(
                f"{name} is deprecated and will be removed in a future release; "
                "create a custom geo_ip_handler instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        return self

    @field_validator("muted_event_types", mode="before")
    def validate_muted_event_types(cls, v: Any) -> frozenset[str]:
        return _validate_muted_event_types_value(v)

    @field_validator("muted_metric_types", mode="before")
    def validate_muted_metric_types(cls, v: Any) -> frozenset[str]:
        return _validate_muted_metric_types_value(v)

    @field_validator("enabled_detection_categories", mode="before")
    def validate_enabled_detection_categories(cls, v: Any) -> frozenset[str]:
        return _validate_enabled_detection_categories_value(v)

    @field_validator("threat_ban_config", mode="before")
    def validate_threat_ban_config(cls, v: Any) -> MappingProxyType[str, Any]:
        return _validate_threat_ban_config_value(v)

    @field_validator("muted_check_logs", mode="before")
    def validate_muted_check_logs(cls, v: Any) -> frozenset[str]:
        return _validate_muted_check_logs_value(v)

    @field_validator("exclude_paths")
    def validate_exclude_paths(cls, v: list[str]) -> list[str]:
        return _validate_exclude_paths_value(v, stacklevel=4)

    def to_agent_config(self) -> "AgentConfig | None":
        if not self.enable_agent or not self.agent_api_key:
            return None

        from guard_core._pydantic_plugin_mute import (
            _mute_pydantic_plugin_instrumentation,
        )

        _mute_pydantic_plugin_instrumentation()

        try:
            from guard_agent import AgentConfig

            kwargs: dict[str, Any] = {
                "api_key": self.agent_api_key,
                "endpoint": self.agent_endpoint,
                "project_id": self.agent_project_id,
                "buffer_size": self.agent_buffer_size,
                "flush_interval": self.agent_flush_interval,
                "dynamic_rule_interval": self.dynamic_rule_interval,
                "status_interval": self.agent_status_interval,
                "high_watermark_ratio": self.agent_high_watermark_ratio,
                "max_concurrent_flushes": self.agent_max_concurrent_flushes,
                "buffer_overflow_policy": self.agent_buffer_overflow_policy,
                "enable_events": self.agent_enable_events,
                "enable_metrics": self.agent_enable_metrics,
                "timeout": self.agent_timeout,
                "retry_attempts": self.agent_retry_attempts,
                "backoff_factor": self.agent_backoff_factor,
                "sensitive_headers": self.agent_sensitive_headers,
                "max_payload_size": self.agent_max_payload_size,
                "project_encryption_key": self.agent_project_encryption_key,
                "guard_version": self.agent_guard_version,
                "guard_core_version": __version__,
                "compression_enabled": self.agent_compression_enabled,
                "compression_threshold": self.agent_compression_threshold,
                "install_id": self.agent_install_id,
                "payload_signing_secret": self.agent_payload_signing_secret,
                "on_error": self.on_error,
            }

            return AgentConfig(
                **{key: value for key, value in kwargs.items() if value is not None}
            )
        except ImportError as e:
            raise AgentPackageNotInstalledError(
                "guard-agent is not installed but enable_agent=True. "
                "Install it with: pip install guard-agent"
            ) from e


class DynamicRules(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str = Field(description="Unique rule ID")
    version: int = Field(description="Rule version number")
    timestamp: datetime = Field(description="Rule creation/update timestamp")
    expires_at: datetime | None = Field(
        default=None, description="Rule expiration time"
    )
    ttl: int = Field(default=300, description="Cache TTL in seconds")

    ip_blacklist: list[str] = Field(default_factory=list, description="IPs to ban")
    ip_whitelist: list[str] = Field(default_factory=list, description="IPs to allow")
    ip_ban_duration: int = Field(default=3600, description="Ban duration in seconds")

    blocked_countries: list[str] = Field(
        default_factory=list, description="Countries to block"
    )
    whitelist_countries: list[str] = Field(
        default_factory=list, description="Countries to allow"
    )

    global_rate_limit: int | None = Field(default=None, description="Global rate limit")
    global_rate_window: int | None = Field(
        default=None, description="Global rate window"
    )
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description="Per-endpoint rate limits {endpoint: (requests, window)}",
    )

    blocked_cloud_providers: set[str] = Field(
        default_factory=set, description="Cloud providers to block"
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="User agents to block"
    )

    suspicious_patterns: list[str] = Field(
        default_factory=list, description="Additional suspicious patterns"
    )

    enable_penetration_detection: bool | None = Field(
        default=None, description="Override penetration detection setting"
    )
    enable_ip_banning: bool | None = Field(
        default=None, description="Override IP banning setting"
    )
    enable_rate_limiting: bool | None = Field(
        default=None, description="Override rate limiting setting"
    )

    emergency_mode: bool = Field(default=False, description="Emergency lockdown mode")
    emergency_whitelist: list[str] = Field(
        default_factory=list, description="Emergency whitelist IPs"
    )
