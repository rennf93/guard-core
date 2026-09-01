from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


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
    auto_ban_threshold: int | None = Field(
        default=None, ge=1, description="Override auto-ban threshold setting"
    )
    auto_ban_duration: int | None = Field(
        default=None, ge=1, description="Override auto-ban duration setting"
    )
    enable_rate_limit_auto_ban: bool | None = Field(
        default=None, description="Override rate-limit auto-ban setting"
    )

    emergency_mode: bool = Field(default=False, description="Emergency lockdown mode")
    emergency_whitelist: list[str] = Field(
        default_factory=list, description="Emergency whitelist IPs"
    )


LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION = 1


class LastKnownDynamicRules(DynamicRules):
    model_config = ConfigDict(extra="forbid")


class LastKnownRulesSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    rules: LastKnownDynamicRules


def dump_last_known_rules_snapshot(rules: DynamicRules) -> str:
    snapshot = LastKnownRulesSnapshot(
        schema_version=LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION,
        rules=LastKnownDynamicRules.model_validate(rules.model_dump()),
    )
    return snapshot.model_dump_json()


def load_last_known_rules_snapshot(payload: str | bytes) -> DynamicRules:
    snapshot = LastKnownRulesSnapshot.model_validate_json(payload)
    if snapshot.schema_version != LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported last-known dynamic rules snapshot schema version: "
            f"{snapshot.schema_version}"
        )
    return DynamicRules.model_validate(snapshot.rules.model_dump())
