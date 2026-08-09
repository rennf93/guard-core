# API Surface Audit

A scoped inventory of the guard-core public API surface (the `SecurityConfig` model and the package exports) with a recommended action per item. The goal is an intuitive, non-bloated, composable surface. This audit is **non-breaking by design**: nothing here removes a field or changes runtime behavior except the two already-deprecated `ipinfo_*` fields, which now emit a runtime `DeprecationWarning` when set.

Current totals (verified against source):

- `SecurityConfig`: **110 fields**, 15 validators, 1 `to_agent_config()` method (`guard_core/models.py`).
- `guard_core` exports: **22** symbols (`guard_core/__init__.py`).
- `fastapi-guard` re-exports: **24** symbols (the 22 above plus its own `SecurityMiddleware` and `__version__`).

Recommendation legend: **Keep** (core/everyday or stable advanced) · **Deprecate** (scheduled for removal, kept working) · **Group?** (candidate for an optional nested sub-config, see [Grouping opportunities](#grouping-opportunities)) · **Remove** (none in this audit, removals are out of scope).

## SecurityConfig fields

Ordered by domain, then by `models.py` line.

| Field | Type | Default | Line | Domain | Recommendation |
|---|---|---|---|---|---|
| `enable_agent` | `bool` | `False` | 457 | agent | Keep |
| `agent_api_key` | `str \| None` | `None` | 461 | agent | Keep |
| `agent_strict` | `bool` | `False` | 465 | agent | Keep |
| `agent_endpoint` | `str` | `"https://api.guard-core.com"` | 484 | agent | Keep · Group? |
| `agent_project_id` | `str \| None` | `None` | 489 | agent | Keep · Group? |
| `agent_buffer_size` | `int` | `100` | 493 | agent | Keep · Group? |
| `agent_flush_interval` | `int` | `30` | 497 | agent | Keep · Group? |
| `agent_enable_events` | `bool` | `True` | 501 | agent | Keep · Group? |
| `agent_enable_metrics` | `bool` | `True` | 505 | agent | Keep · Group? |
| `agent_timeout` | `int` | `30` | 509 | agent | Keep · Group? |
| `agent_retry_attempts` | `int` | `3` | 513 | agent | Keep · Group? |
| `agent_project_encryption_key` | `str \| None` | `None` | 517 | agent | Keep · Group? |
| `agent_guard_version` | `str \| None` | `None` | 527 | agent | Keep · Group? |
| `agent_high_watermark_ratio` | `float \| None` | `None` | 537 | agent | Keep · Group? |
| `agent_max_concurrent_flushes` | `int \| None` | `None` | 545 | agent | Keep · Group? |
| `agent_buffer_overflow_policy` | `Literal["drop","block","raise"] \| None` | `None` | 553 | agent | Keep · Group? |
| `agent_backoff_factor` | `float \| None` | `None` | 564 | agent | Keep · Group? |
| `agent_sensitive_headers` | `list[str] \| None` | `None` | 572 | agent | Keep · Group? |
| `agent_max_payload_size` | `int \| None` | `None` | 580 | agent | Keep · Group? |
| `agent_compression_enabled` | `bool \| None` | `None` | 588 | agent | Keep · Group? |
| `agent_compression_threshold` | `int \| None` | `None` | 597 | agent | Keep · Group? |
| `agent_install_id` | `str \| None` | `None` | 605 | agent | Keep · Group? |
| `agent_payload_signing_secret` | `str \| None` | `None` | 613 | agent | Keep · Group? |
| `agent_status_interval` | `int` | `300` | 626 | agent | Keep · Group? |
| `auto_ban_threshold` | `int` | `10` | 204 | auto-ban | Keep |
| `auto_ban_duration` | `int` | `3600` | 208 | auto-ban | Keep |
| `threat_ban_config` | `dict[str, ThreatBanConfig]` | `dict` | 212 | auto-ban | Keep |
| `global_behavior_rules` | `list[BehaviorRuleConfig]` | `list` | 220 | behavioral | Keep |
| `block_cloud_providers` | `set[str] \| None` | `None` | 331 | cloud | Keep |
| `cloud_ip_refresh_interval` | `int` | `3600` | 340 | cloud | Keep |
| `cloud_ip_store` | `CloudIpStoreProtocol \| CloudIpStoreFactory \| None` | `None` | 373 | cloud | Keep |
| `enable_cors` | `bool` | `False` | 304 | cors | Keep |
| `cors_allow_origins` | `list[str]` | `["*"]` | 306 | cors | Keep · Group? |
| `cors_allow_methods` | `list[str]` | `[GET,POST,PUT,PATCH,DELETE,OPTIONS]` | 310 | cors | Keep · Group? |
| `cors_allow_headers` | `list[str]` | `["*"]` | 315 | cors | Keep · Group? |
| `cors_allow_credentials` | `bool` | `False` | 319 | cors | Keep · Group? |
| `cors_expose_headers` | `list[str]` | `list` | 323 | cors | Keep · Group? |
| `cors_max_age` | `int` | `600` | 327 | cors | Keep · Group? |
| `whitelist_countries` | `frozenset[str]` | `frozenset` | 185 | geo/country | Keep |
| `blocked_countries` | `frozenset[str]` | `frozenset` | 195 | geo/country | Keep |
| `geo_ip_handler` | `GeoIPHandler \| None` | `None` | 98 | geo/country | Keep |
| `geo_ip_db_max_age` | `int` | `86400` | 366 | geo/country | Keep |
| `detection_compiler_timeout` | `float` | `2.0` | 647 | detection | Keep · Group? |
| `detection_max_content_length` | `int` | `10000` | 654 | detection | Keep · Group? |
| `detection_max_body_inspect_bytes` | `int` | `262144` | 661 | detection | Keep · Group? |
| `detection_preserve_attack_patterns` | `bool` | `True` | 674 | detection | Keep · Group? |
| `detection_semantic_threshold` | `float` | `0.7` | 679 | detection | Keep · Group? |
| `detection_anomaly_threshold` | `float` | `3.0` | 686 | detection | Keep · Group? |
| `detection_slow_pattern_threshold` | `float` | `0.1` | 693 | detection | Keep · Group? |
| `detection_monitor_history_size` | `int` | `1000` | 700 | detection | Keep · Group? |
| `detection_max_tracked_patterns` | `int` | `1000` | 707 | detection | Keep · Group? |
| `detection_threat_score_threshold` | `float` | `1.0` | 714 | detection | Keep · Group? |
| `detection_scan_body` | `bool` | `True` | 801 | detection | Keep · Group? |
| `enabled_detection_categories` | `set[str]` | `ALL_DETECTION_CATEGORIES` | 809 | detection | Keep |
| `excluded_detection_headers` | `set[str]` | `set` | 780 | detection (excl.) | Keep |
| `excluded_detection_params` | `set[str]` | `set` | 787 | detection (excl.) | Keep |
| `excluded_detection_body_fields` | `set[str]` | `set` | 793 | detection (excl.) | Keep |
| `enable_penetration_detection` | `bool` | `True` | 404 | detection | Keep |
| `enable_dynamic_rules` | `bool` | `False` | 618 | dynamic-rules | Keep |
| `dynamic_rule_interval` | `int` | `300` | 622 | dynamic-rules | Keep |
| `emergency_mode` | `bool` | `False` | 633 | dynamic-rules | Keep |
| `emergency_whitelist` | `list[str]` | `list` | 637 | dynamic-rules | Keep |
| `endpoint_rate_limits` | `dict[str, tuple[int, int]]` | `dict` | 642 | dynamic-rules | Keep |
| `enable_enrichment` | `bool` | `False` | 769 | enrichment | Keep |
| `ipinfo_token` | `str \| None` | `None` | 445 | ipinfo | **Deprecate (warns)** |
| `ipinfo_db_path` | `Path \| None` | `Path("data/ipinfo/country_asn.mmdb")` | 451 | ipinfo | **Deprecate (warns)** |
| `custom_log_file` | `str \| None` | `None` | 228 | logging | Keep |
| `log_suspicious_level` | `Literal[...] \| None` | `"WARNING"` | 233 | logging | Keep |
| `log_request_level` | `Literal[...] \| None` | `None` | 237 | logging | Keep |
| `log_country_check_level` | `Literal[...] \| None` | `"INFO"` | 241 | logging | Keep |
| `log_format` | `Literal["text","json"]` | `"text"` | 253 | logging | Keep |
| `enable_logfire` | `bool` | `False` | 759 | logfire | Keep |
| `logfire_service_name` | `str` | `"guard-core"` | 764 | logfire | Keep |
| `muted_event_types` | `set[str]` | `set` | 721 | muted | Keep |
| `muted_metric_types` | `set[str]` | `set` | 726 | muted | Keep |
| `muted_check_logs` | `set[str]` | `set` | 731 | muted | Keep |
| `enable_otel` | `bool` | `False` | 736 | otel | Keep |
| `otel_service_name` | `str` | `"guard-core"` | 741 | otel | Keep · Group? |
| `otel_exporter_endpoint` | `str \| None` | `None` | 746 | otel | Keep · Group? |
| `otel_resource_attributes` | `dict[str, str]` | `dict` | 751 | otel | Keep · Group? |
| `trusted_proxies` | `list[str]` | `list` | 78 | proxy | Keep |
| `trusted_proxy_depth` | `int` | `1` | 83 | proxy | Keep |
| `trust_x_forwarded_proto` | `bool` | `False` | 88 | proxy | Keep |
| `rate_limit` | `int` | `10` | 262 | rate-limit | Keep |
| `rate_limit_window` | `int` | `60` | 266 | rate-limit | Keep |
| `enable_rate_limiting` | `bool` | `True` | 400 | rate-limit | Keep |
| `enable_redis` | `bool` | `True` | 103 | redis | Keep |
| `redis_url` | `str \| None` | `"redis://localhost:6379"` | 108 | redis | Keep |
| `redis_prefix` | `str` | `"guard_core:"` | 113 | redis | Keep |
| `redis_socket_connect_timeout` | `float \| None` | `2.0` | 118 | redis | Keep · Group? |
| `redis_socket_timeout` | `float \| None` | `2.0` | 130 | redis | Keep · Group? |
| `redis_health_check_interval` | `int` | `30` | 141 | redis | Keep · Group? |
| `redis_max_connections` | `int \| None` | `None` | 151 | redis | Keep · Group? |
| `redis_retries` | `int` | `1` | 159 | redis | Keep · Group? |
| `redis_fail_open` | `bool` | `False` | 418 | redis | Keep |
| `security_headers` | `dict[str, Any] \| None` | headers dict | 274 | security-headers | Keep |
| `enforce_https` | `bool` | `False` | 270 | security-headers | Keep |
| `whitelist` | `list[str] \| None` | `None` | 168 | allow/deny | Keep |
| `blacklist` | `list[str]` | `list` | 177 | allow/deny | Keep |
| `blocked_user_agents` | `list[str]` | `list` | 200 | allow/deny | Keep |
| `enable_ip_banning` | `bool` | `True` | 396 | ip-banning | Keep |
| `passive_mode` | `bool` | `False` | 93 | mode | Keep |
| `custom_error_responses` | `dict[int, str]` | `dict` | 258 | hooks | Keep |
| `custom_request_check` | `Callable[...] \| None` | `None` | 293 | hooks | Keep |
| `custom_response_modifier` | `Callable[...] \| None` | `None` | 297 | hooks | Keep |
| `on_error` | `Callable[[str, BaseException, dict], None] \| None` | `None` | 474 | hooks | Keep |
| `lazy_init` | `bool` | `True` | 347 | init | Keep |
| `exclude_paths` | `list[str]` | docs/static defaults | 384 | init | Keep |
| `fail_secure` | `bool` | `True` | 408 | failure-mode | Keep |
| `route_resolution_strict` | `bool` | `False` | 430 | failure-mode | Keep |

No field is required (every field has a default or `default_factory`).

## Field counts by domain

- agent: 24
- detection (incl. 3 `excluded_detection_*` + `enable_penetration_detection`): 16
- redis: 9
- hooks: 4 · logging: 5 · geo/country: 4 · otel: 4
- cors: 7 · dynamic-rules: 5
- auto-ban: 3 · cloud: 3 · muted: 3 · proxy: 3 · rate-limit: 3 · allow/deny: 3
- security-headers: 2 · ipinfo: 2 · logfire: 2 · init: 2 · failure-mode: 2
- behavioral: 1 · enrichment: 1 · ip-banning: 1 · mode: 1

**Total: 110 fields.**

## Deprecations (wired in this audit)

`ipinfo_token` and `ipinfo_db_path` have self-described as *Deprecated* for some time, directing users to a custom `geo_ip_handler`. They now emit a runtime `DeprecationWarning` **when explicitly set**: the warning is raised from a `model_validator` keyed on `model_fields_set`, so it fires once at construction and never on internal access or when the field is left at its default.

```text
ipinfo_token is deprecated and will be removed in a future release;
create a custom geo_ip_handler instead.
```

- Non-breaking: both fields keep working; the engine still auto-builds an `IPInfoManager` from them when country lists are set and no `geo_ip_handler` is supplied (`validate_geo_ip_handler_exists`).
- Removal target: a future **major** release. Until then, migrate by passing a `geo_ip_handler` (any `GeoIPHandler`) directly.
- The suite filters this specific warning (`pyproject.toml` `filterwarnings`) so existing fixtures stay quiet; dedicated tests assert it still fires.

## Grouping opportunities

Four prefixes dominate the field count and are good candidates for **optional** nested sub-config models (e.g. `config.agent.*`, `config.cors.*`, `config.detection.*`, `config.otel.*`): agent (24), detection (16), cors (7), otel (4). Presented as an option, **not applied**, because of the trade-offs:

- **For:** smaller top-level namespace; related knobs discoverable together; clearer typing per concern.
- **Against (breaking unless aliased):** the current flat construction (`SecurityConfig(agent_api_key=..., cors_allow_origins=...)`) is the documented, intuitive surface the design partner likes. Any grouping must ship as a **non-breaking additive alias layer** (accept both flat and nested, keep flat in `__init__` signatures) or it breaks every existing call site.

Recommendation: defer. If pursued, do it as an additive alias layer behind its own change with a migration note, never as a silent restructure.

## Exports

`guard_core/__init__.py` `__all__` (22): `SecurityConfig`, `SecurityDecorator`, `RouteConfig`, `BehaviorTracker`, `BehaviorRule`, `ip_ban_manager`, `IPBanManager`, `cloud_handler`, `CloudManager`, `IPInfoManager`, `rate_limit_handler`, `RateLimitManager`, `redis_handler`, `RedisManager`, `security_headers_manager`, `SecurityHeadersManager`, `sus_patterns_handler`, `GeoIPHandler`, `RedisHandlerProtocol`, `GuardRequest`, `GuardResponse`, `GuardResponseFactory`.

`fastapi-guard/guard/__init__.py` `__all__` (24): the 22 above + the fastapi-guard-only `SecurityMiddleware` and `__version__`.

**Drift status: none today** (the two lists agree, 24 = 22 + 2). The risk is future drift, because fastapi-guard hand-duplicates the 22 names. Single source of truth: fastapi-guard derives its `__all__` from `guard_core.__all__` plus its two locals, and a test asserts every exported name is importable, so a new guard-core export can't silently go missing downstream. `IPInfoManager` stays exported even though `ipinfo_*` config is deprecated; custom `geo_ip_handler` implementations may still construct it directly.

## Validators & methods (reference)

`warn_unknown_fields` (819) · `validate_ip_lists` (839) · `validate_trusted_proxies` (857) · `validate_proxy_depth` (875) · `coerce_country_set` (881) · `validate_cloud_providers` (891) · `validate_optional_extras_installed` (897) · `validate_geo_ip_handler_exists` (921) · `validate_agent_config` (950) · `warn_deprecated_fields` (969, this audit) · `validate_muted_event_types` · `validate_muted_metric_types` · `validate_enabled_detection_categories` · `validate_threat_ban_config` · `validate_muted_check_logs` · `to_agent_config` (method). 15 validators total.
