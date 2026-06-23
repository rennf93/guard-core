from collections.abc import Awaitable, Callable
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

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


CloudProvider = Literal["AWS", "GCP", "Azure"]
VALID_CLOUD_PROVIDERS: frozenset[str] = frozenset(get_args(CloudProvider))


class ThreatBanConfig(BaseModel):
    threshold: int = Field(ge=1, description="Number of detections before auto-ban.")
    duration: int = Field(ge=1, description="Ban duration in seconds.")


class BehaviorRuleConfig(BaseModel):
    rule_type: Literal["usage", "return_pattern", "frequency"]
    threshold: int = Field(ge=1)
    window: int = Field(default=3600, ge=1)
    pattern: str | None = None
    action: Literal["ban", "log", "throttle", "alert"] = "log"
    ban_duration: int | None = Field(default=None, ge=1)
    correlate_with_detection: bool = False


class SecurityConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    trusted_proxies: list[str] = Field(
        default_factory=list,
        description="List of trusted proxy IPs or CIDR ranges for X-Forwarded-For",
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

    whitelist: list[str] | None = Field(
        default=None,
        description=(
            "Allowed IP addresses or CIDR ranges. A non-empty whitelist is "
            "restrictive: only listed IPs pass the global IP check. An explicit "
            "whitelist match overrides the blacklist; dynamic IP bans still apply."
        ),
    )

    blacklist: list[str] = Field(
        default_factory=list,
        description=(
            "Blocked IP addresses or CIDR ranges. Enforced ahead of country and "
            "cloud-provider checks, but overridden by an explicit whitelist match."
        ),
    )

    whitelist_countries: frozenset[str] = Field(
        default_factory=frozenset,
        description="Country codes that are always allowed",
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

    threat_ban_config: dict[str, ThreatBanConfig] = Field(
        default_factory=dict,
        description=(
            "Per-category ban thresholds and durations. "
            "Unlisted categories fall back to auto_ban_threshold / auto_ban_duration."
        ),
    )

    global_behavior_rules: list[BehaviorRuleConfig] = Field(
        default_factory=list,
        description=(
            "Behaviour rules applied to every route, in addition to any "
            "decorator-specified rules. Useful for global 404 tracking."
        ),
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

    block_cloud_providers: set[str] | None = Field(
        default=None,
        description=(
            "Cloud providers to block. A bare provider ('GCP') blocks the whole "
            "provider; a region carve-out ('GCP:!us-central1') blocks the provider "
            "except that region. Region scoping is supported for GCP and AWS."
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
            "geo-IP MMDB downloads to a background task started at app boot, "
            "so the application does not block on multi-second network calls. "
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

    enable_dynamic_rules: bool = Field(
        default=False, description="Enable dynamic rule updates from SaaS platform"
    )

    dynamic_rule_interval: int = Field(
        default=300, description="Interval in seconds between dynamic rule updates"
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

    muted_event_types: set[str] = Field(
        default_factory=set,
        description="Event types to mute from telemetry dispatch",
    )

    muted_metric_types: set[str] = Field(
        default_factory=set,
        description="Metric types to mute from telemetry dispatch",
    )

    muted_check_logs: set[str] = Field(
        default_factory=set,
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
            "Top-level JSON body keys to exclude from penetration detection scanning."
        ),
    )
    enabled_detection_categories: set[str] = Field(
        default_factory=lambda: set(ALL_DETECTION_CATEGORIES),
        description=(
            "Detection categories to scan for. Defaults to all. "
            f"Valid values: {sorted(ALL_DETECTION_CATEGORIES)}"
        ),
    )

    @field_validator("whitelist", "blacklist")
    def validate_ip_lists(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None

        validated = []
        for entry in v:
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = ip_address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid IP or CIDR range: {entry}") from None
        return validated

    @field_validator("trusted_proxies")
    def validate_trusted_proxies(cls, v: list[str]) -> list[str]:
        if not v:
            return []

        validated = []
        for entry in v:
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = ip_address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid proxy IP or CIDR range: {entry}") from None
        return validated

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
    def validate_cloud_providers(cls, v: Any) -> set[str]:
        if v is None:
            return set()
        return {sel for sel in v if sel.partition(":!")[0] in VALID_CLOUD_PROVIDERS}

    @model_validator(mode="after")
    def validate_geo_ip_handler_exists(self) -> Self:
        if self.geo_ip_handler is None and (
            self.blocked_countries or self.whitelist_countries
        ):
            if self.ipinfo_token:
                from guard_core.handlers.ipinfo_handler import IPInfoManager

                self.geo_ip_handler = IPInfoManager(
                    token=self.ipinfo_token,
                    db_path=self.ipinfo_db_path,
                )
            else:
                raise ValueError(
                    "geo_ip_handler is required "
                    "if blocked_countries or whitelist_countries is set"
                )
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

    @field_validator("muted_event_types")
    def validate_muted_event_types(cls, v: set[str]) -> set[str]:
        from guard_core.core.events.event_types import EVENT_TYPE_VALUES

        invalid = v - EVENT_TYPE_VALUES
        if invalid:
            raise ValueError(
                f"Unknown event types in muted_event_types: {sorted(invalid)}. "
                f"Valid: {sorted(EVENT_TYPE_VALUES)}"
            )
        return v

    @field_validator("muted_metric_types")
    def validate_muted_metric_types(cls, v: set[str]) -> set[str]:
        from guard_core.core.events.event_types import METRIC_TYPE_VALUES

        invalid = v - METRIC_TYPE_VALUES
        if invalid:
            raise ValueError(
                f"Unknown metric types in muted_metric_types: {sorted(invalid)}. "
                f"Valid: {sorted(METRIC_TYPE_VALUES)}"
            )
        return v

    @field_validator("enabled_detection_categories")
    def validate_enabled_detection_categories(cls, v: set[str]) -> set[str]:
        unknown = v - ALL_DETECTION_CATEGORIES
        if unknown:
            raise ValueError(
                f"Unknown detection categories: {sorted(unknown)}. "
                f"Valid: {sorted(ALL_DETECTION_CATEGORIES)}"
            )
        return v

    @field_validator("threat_ban_config")
    def validate_threat_ban_config(
        cls, v: dict[str, ThreatBanConfig]
    ) -> dict[str, ThreatBanConfig]:
        unknown = set(v.keys()) - ALL_DETECTION_CATEGORIES
        if unknown:
            raise ValueError(
                f"Unknown threat categories in threat_ban_config: {sorted(unknown)}. "
                f"Valid: {sorted(ALL_DETECTION_CATEGORIES)}"
            )
        return v

    @field_validator("muted_check_logs")
    def validate_muted_check_logs(cls, v: set[str]) -> set[str]:
        from guard_core.core.events.event_types import CHECK_NAME_VALUES

        invalid = v - CHECK_NAME_VALUES
        if invalid:
            raise ValueError(
                f"Unknown check names in muted_check_logs: {sorted(invalid)}. "
                f"Valid: {sorted(CHECK_NAME_VALUES)}"
            )
        return v

    def to_agent_config(self) -> "AgentConfig | None":
        if not self.enable_agent or not self.agent_api_key:
            return None

        try:
            from guard_agent import AgentConfig

            return AgentConfig(
                api_key=self.agent_api_key,
                endpoint=self.agent_endpoint,
                project_id=self.agent_project_id,
                buffer_size=self.agent_buffer_size,
                flush_interval=self.agent_flush_interval,
                dynamic_rule_interval=self.dynamic_rule_interval,
                status_interval=self.agent_status_interval,
                enable_events=self.agent_enable_events,
                enable_metrics=self.agent_enable_metrics,
                timeout=self.agent_timeout,
                retry_attempts=self.agent_retry_attempts,
                project_encryption_key=self.agent_project_encryption_key,
                guard_version=self.agent_guard_version,
            )
        except ImportError:
            return None


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
