---

title: Models
description: API reference for guard-core's Pydantic models including SecurityConfig and DynamicRules
keywords: models, security config, dynamic rules, pydantic, guard-core
---

Models
======

The `models` module defines the Pydantic data models that configure guard-core's behavior.

___

SecurityConfig
--------------

The primary configuration model for guard-core. All security settings are defined here.

```python
class SecurityConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    trusted_proxies: list[str] = Field(default_factory=list)
    trusted_proxy_depth: int = Field(default=1)
    trust_x_forwarded_proto: bool = Field(default=False)

    passive_mode: bool = Field(default=False)

    geo_ip_handler: GeoIPHandler | None = Field(default=None)

    enable_redis: bool = Field(default=True)
    redis_url: str | None = Field(default="redis://localhost:6379")
    redis_prefix: str = Field(default="guard_core:")

    whitelist: list[str] | None = Field(default=None)
    blacklist: list[str] = Field(default_factory=list)
    whitelist_countries: list[str] = Field(default_factory=list)
    blocked_countries: list[str] = Field(default_factory=list)
    blocked_user_agents: list[str] = Field(default_factory=list)

    auto_ban_threshold: int = Field(default=10)
    auto_ban_duration: int = Field(default=3600)

    custom_log_file: str | None = Field(default=None)
    log_suspicious_level: Literal[
        "INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"
    ] | None = Field(default="WARNING")
    log_request_level: Literal[
        "INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"
    ] | None = Field(default=None)
    log_format: Literal["text", "json"] = Field(default="text")

    custom_error_responses: dict[int, str] = Field(default_factory=dict)

    rate_limit: int = Field(default=10)
    rate_limit_window: int = Field(default=60)

    enforce_https: bool = Field(default=False)

    security_headers: dict[str, Any] | None = Field(default_factory=...)

    custom_request_check: Callable[
        [GuardRequest], Awaitable[GuardResponse | None]
    ] | None = Field(default=None)
    custom_response_modifier: Callable[
        [GuardResponse], Awaitable[GuardResponse]
    ] | None = Field(default=None)

    enable_cors: bool = Field(default=False)
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_methods: list[str] = Field(
        default_factory=lambda: [
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ]
    )
    cors_allow_headers: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_credentials: bool = Field(default=False)
    cors_expose_headers: list[str] = Field(default_factory=list)
    cors_max_age: int = Field(default=600)

    block_cloud_providers: set[str] | None = Field(default=None)
    cloud_ip_refresh_interval: int = Field(default=3600, ge=60, le=86400)

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs", "/redoc", "/openapi.json",
            "/openapi.yaml", "/favicon.ico", "/static",
        ]
    )

    enable_ip_banning: bool = Field(default=True)
    enable_rate_limiting: bool = Field(default=True)
    enable_penetration_detection: bool = Field(default=True)

    ipinfo_token: str | None = Field(default=None)
    ipinfo_db_path: Path | None = Field(
        default=Path("data/ipinfo/country_asn.mmdb")
    )

    enable_agent: bool = Field(default=False)
    agent_api_key: str | None = Field(default=None)
    agent_endpoint: str = Field(
        default="https://api.fastapi-guard.com"
    )
    agent_project_id: str | None = Field(default=None)
    agent_buffer_size: int = Field(default=100)
    agent_flush_interval: int = Field(default=30)
    agent_enable_events: bool = Field(default=True)
    agent_enable_metrics: bool = Field(default=True)
    agent_timeout: int = Field(default=30)
    agent_retry_attempts: int = Field(default=3)

    enable_dynamic_rules: bool = Field(default=False)
    dynamic_rule_interval: int = Field(default=300)

    emergency_mode: bool = Field(default=False)
    emergency_whitelist: list[str] = Field(default_factory=list)
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict
    )

    detection_compiler_timeout: float = Field(
        default=2.0, ge=0.1, le=10.0
    )
    detection_max_content_length: int = Field(
        default=10000, ge=1000, le=100000
    )
    detection_preserve_attack_patterns: bool = Field(default=True)
    detection_semantic_threshold: float = Field(
        default=0.7, ge=0.0, le=1.0
    )
    detection_anomaly_threshold: float = Field(
        default=3.0, ge=1.0, le=10.0
    )
    detection_slow_pattern_threshold: float = Field(
        default=0.1, ge=0.01, le=1.0
    )
    detection_monitor_history_size: int = Field(
        default=1000, ge=100, le=10000
    )
    detection_max_tracked_patterns: int = Field(
        default=1000, ge=100, le=5000
    )

    def to_agent_config(self) -> "AgentConfig | None":
        """
        Build an AgentConfig from this SecurityConfig, or None if the agent
        is not enabled or guard-agent is not installed.
        """
```

### Validators

| Validator | Fields | Purpose |
|-----------|--------|---------|
| `validate_ip_lists` | `whitelist`, `blacklist` | Validates IP addresses and CIDR ranges |
| `validate_trusted_proxies` | `trusted_proxies` | Validates proxy IP addresses and CIDR ranges |
| `validate_proxy_depth` | `trusted_proxy_depth` | Ensures depth is at least 1 |
| `validate_cloud_providers` | `block_cloud_providers` | Filters to valid providers: AWS, GCP, Azure |
| `validate_geo_ip_handler_exists` | model-level | Requires `geo_ip_handler` when country filtering is configured |
| `validate_agent_config` | model-level | Requires `agent_api_key` when agent is enabled |

___

DynamicRules
------------

Model for rules pushed dynamically from the Guard Agent SaaS platform.

```python
class DynamicRules(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str = Field(description="Unique rule ID")
    version: int = Field(description="Rule version number")
    timestamp: datetime = Field(description="Rule creation/update timestamp")
    expires_at: datetime | None = Field(default=None)
    ttl: int = Field(default=300)

    ip_blacklist: list[str] = Field(default_factory=list)
    ip_whitelist: list[str] = Field(default_factory=list)
    ip_ban_duration: int = Field(default=3600)

    blocked_countries: list[str] = Field(default_factory=list)
    whitelist_countries: list[str] = Field(default_factory=list)

    global_rate_limit: int | None = Field(default=None)
    global_rate_window: int | None = Field(default=None)
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict
    )

    blocked_cloud_providers: set[str] = Field(default_factory=set)
    blocked_user_agents: list[str] = Field(default_factory=list)
    suspicious_patterns: list[str] = Field(default_factory=list)

    enable_penetration_detection: bool | None = Field(default=None)
    enable_ip_banning: bool | None = Field(default=None)
    enable_rate_limiting: bool | None = Field(default=None)

    emergency_mode: bool = Field(default=False)
    emergency_whitelist: list[str] = Field(default_factory=list)
```
