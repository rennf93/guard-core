---

title: Ban Configuration
description: API reference for ThreatBanConfig and the per-category ban policy on SecurityConfig
keywords: threat ban config, per-category ban, auto ban, guard-core
---

Ban Configuration
=================

`ThreatBanConfig` is the per-category ban policy model. Combined with `SecurityConfig.threat_ban_config: dict[str, ThreatBanConfig]`, it lets each detection category carry its own threshold and ban duration. Categories not present in the dict fall through to the flat `auto_ban_threshold` / `auto_ban_duration` policy.

___

ThreatBanConfig
---------------

```python
class ThreatBanConfig(BaseModel):
    threshold: int = Field(ge=1)
    duration: int = Field(ge=1)
```

| Field       | Type | Description                                                  |
|-------------|------|--------------------------------------------------------------|
| `threshold` | `int` | Number of detections in this category before auto-ban (>= 1). |
| `duration`  | `int` | Ban duration in seconds (>= 1).                              |

___

SecurityConfig.threat_ban_config
--------------------------------

```python
class SecurityConfig(BaseModel):
    threat_ban_config: dict[str, ThreatBanConfig] = Field(default_factory=dict)
```

Keys must be valid category names from `ALL_DETECTION_CATEGORIES`. The validator rejects unknown keys with a `ValidationError`.

___

How the policy is applied
-------------------------

Every regex hit increments `suspicious_request_counts[ip][category]`. After a hit, the suspicious-activity check evaluates the bans in this order:

1. **Per-category ban** — for each category in the current detection result, look it up in `threat_ban_config`. If the IP's count for that category has reached or exceeded the entry's `threshold`, ban the IP with `entry.duration` seconds. The audit log carries `reason="penetration_attempt:<category>"`.
2. **Flat-threshold fallback** — if no per-category ban fired, sum all category counts for this IP. If the total has reached `auto_ban_threshold`, ban the IP for `auto_ban_duration` seconds. The audit log carries `reason="penetration_attempt"`.

If neither threshold is met, the request is rejected (status 400) but the IP is not banned.

___

Block vs ban
------------

A block is a decision about one request: it is rejected and nothing about the origin is stored, so the next request from the same IP is evaluated from scratch. A ban is a decision about the IP: it is stored with an expiry and every later request from it is rejected by `IpSecurityCheck._check_banned_ip` before the remaining checks run. The caller sees the same 403 either way; the difference is entirely server-side.

| Aspect | Block | Ban |
|--------|-------|-----|
| Client sees | 403 (400 for an unbanned detection hit) | 403 |
| State retained | none | IP plus expiry, in `TTLCache` and in Redis when configured |
| Next request | full pipeline runs again | short-circuits at the ban check |
| Lifetime | that one request | `auto_ban_duration` (default 3600s) or the matching `ThreatBanConfig.duration` |

### Cost of a banned request

The ban lookup is the first thing `IpSecurityCheck` does, and `IpSecurityCheck` is registered ahead of `CloudProviderCheck`, `UserAgentCheck`, `RateLimitCheck` and `SuspiciousActivityCheck`. A banned IP therefore skips the country and cloud-provider lookups, user-agent matching, rate-limit bookkeeping and the whole payload detection sweep. Checks registered before it (route config, emergency mode, HTTPS enforcement, request size, required headers, authentication, referrer, custom validators, time window) still run, so a ban is a cheaper request, not a free one.

### Logging

A banned request is not silent. It emits one `log_activity` line at `log_suspicious_level` with `reason="Banned IP attempted access: <ip>"`, plus one `ip_blocked` event carrying `filter_type="banned"`. A fresh detection hit typically writes two lines (the detection and the block), so bans reduce log volume rather than eliminate it. Suppress the line with `muted_check_logs={"ip_security"}`.

### exclude_paths takes precedence

`exclude_paths` is evaluated in `BypassHandler.handle_passthrough`, before the client IP is extracted and before any check runs. A banned IP still reaches an excluded path. Reserve `exclude_paths` for endpoints that are safe to serve unconditionally.

### Without Redis

Bans live only in the process-local `TTLCache` (`maxsize=10000`, `ttl=3600`). They are still enforced, but each worker process keeps its own set, so an IP banned by one worker is unknown to the others until it misbehaves there too, and a restart clears every ban. A `duration` above `LOCAL_CACHE_TTL_CAP_SECONDS` (3600) raises `ValueError` in this mode, since the local cache cannot outlive its own TTL. With Redis attached, the ban is shared across every process and survives restarts.

### Passive mode

Passive mode never bans. Per-category counters still increment and the detection is still logged and reported, but `_handle_suspicious_passive_mode` returns without calling `ban_ip`, and an already-banned IP is logged with `action_taken="logged_only"` instead of being rejected. Bans also require `enable_ip_banning` to stay `True`.

___

Example
-------

Single-strike ban for SQL injection (week-long), 3-strike ban for XSS (one day), and the default flat policy for everything else:

```python
from guard_core.models import SecurityConfig, ThreatBanConfig

config = SecurityConfig(
    auto_ban_threshold=10,
    auto_ban_duration=3600,
    threat_ban_config={
        "sqli": ThreatBanConfig(threshold=1, duration=604800),
        "xss": ThreatBanConfig(threshold=3, duration=86400),
    },
)
```

A SQL injection hit on the first request bans the IP for one week with `reason="penetration_attempt:sqli"`. An XSS attempt on the third request bans for one day with `reason="penetration_attempt:xss"`. Twenty mixed `cmd_injection` and `recon` hits eventually trip the flat threshold and produce `reason="penetration_attempt"`.

___

See also
--------

- [SecurityConfig - Per-Category Bans](../configuration/security-config.md#per-category-bans)
- [Models - ThreatBanConfig](models.md#threatbanconfig)
- [DetectionResult](detection-result.md)
