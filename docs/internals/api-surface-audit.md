# API Surface Audit

A scoped inventory of the guard-core public API surface — the `SecurityConfig`
model and the package exports — with a recommended action per item. The goal is
an intuitive, non-bloated, composable surface. This audit is **non-breaking by
design**: nothing here removes a field or changes runtime behavior except the
two already-deprecated `ipinfo_*` fields, which now emit a runtime
`DeprecationWarning` when set.

Current totals (verified against source):

- `SecurityConfig`: **90 fields**, 13 validators, 1 `to_agent_config()` method
  (`guard_core/models.py`).
- `guard_core` exports: **22** symbols (`guard_core/__init__.py`).
- `fastapi-guard` re-exports: **24** symbols (the 22 above plus its own
  `SecurityMiddleware` and `__version__`).

Recommendation legend: **Keep** (core/everyday or stable advanced) · **Deprecate**
(scheduled for removal, kept working) · **Group?** (candidate for an optional
nested sub-config, see [Grouping opportunities](#grouping-opportunities)) ·
**Remove** (none in this audit — removals are out of scope).

## SecurityConfig fields

Ordered by domain, then by `models.py` line.

| Field | Type | Default | Line | Domain | Recommendation |
|---|---|---|---|---|---|
| `enable_agent` | `bool` | `False` | 325 | agent | Keep |
| `agent_api_key` | `str \| None` | `None` | 329 | agent | Keep |
| `agent_strict` | `bool` | `False` | 333 | agent | Keep |
| `agent_endpoint` | `str` | `"https://api.guard-core.com"` | 352 | agent | Keep · Group? |
| `agent_project_id` | `str \| None` | `None` | 357 | agent | Keep · Group? |
| `agent_buffer_size` | `int` | `100` | 361 | agent | Keep · Group? |
| `agent_flush_interval` | `int` | `30` | 365 | agent | Keep · Group? |
| `agent_enable_events` | `bool` | `True` | 369 | agent | Keep · Group? |
| `agent_enable_metrics` | `bool` | `True` | 373 | agent | Keep · Group? |
| `agent_timeout` | `int` | `30` | 377 | agent | Keep · Group? |
| `agent_retry_attempts` | `int` | `3` | 381 | agent | Keep · Group? |
| `agent_project_encryption_key` | `str \| None` | `None` | 385 | agent | Keep · Group? |
| `agent_guard_version` | `str \| None` | `None` | 395 | agent | Keep · Group? |
| `agent_status_interval` | `int` | `300` | 413 | agent | Keep · Group? |
| `auto_ban_threshold` | `int` | `10` | 117 | auto-ban | Keep |
| `auto_ban_duration` | `int` | `3600` | 121 | auto-ban | Keep |
| `threat_ban_config` | `dict[str, ThreatBanConfig]` | `dict` | 125 | auto-ban | Keep |
| `global_behavior_rules` | `list[BehaviorRuleConfig]` | `list` | 133 | behavioral | Keep |
| `block_cloud_providers` | `set[str] \| None` | `None` | 232 | cloud | Keep |
| `cloud_ip_refresh_interval` | `int` | `3600` | 241 | cloud | Keep |
| `cloud_ip_store` | `CloudIpStoreProtocol \| CloudIpStoreFactory \| None` | `None` | 268 | cloud | Keep |
| `enable_cors` | `bool` | `False` | 205 | cors | Keep |
| `cors_allow_origins` | `list[str]` | `["*"]` | 207 | cors | Keep · Group? |
| `cors_allow_methods` | `list[str]` | `[GET,POST,PUT,PATCH,DELETE,OPTIONS]` | 211 | cors | Keep · Group? |
| `cors_allow_headers` | `list[str]` | `["*"]` | 216 | cors | Keep · Group? |
| `cors_allow_credentials` | `bool` | `False` | 220 | cors | Keep · Group? |
| `cors_expose_headers` | `list[str]` | `list` | 224 | cors | Keep · Group? |
| `cors_max_age` | `int` | `600` | 228 | cors | Keep · Group? |
| `whitelist_countries` | `frozenset[str]` | `frozenset` | 103 | geo/country | Keep |
| `blocked_countries` | `frozenset[str]` | `frozenset` | 108 | geo/country | Keep |
| `geo_ip_handler` | `GeoIPHandler \| None` | `None` | 66 | geo/country | Keep |
| `geo_ip_db_max_age` | `int` | `86400` | 261 | geo/country | Keep |
| `detection_compiler_timeout` | `float` | `2.0` | 434 | detection | Keep · Group? |
| `detection_max_content_length` | `int` | `10000` | 441 | detection | Keep · Group? |
| `detection_preserve_attack_patterns` | `bool` | `True` | 448 | detection | Keep · Group? |
| `detection_semantic_threshold` | `float` | `0.7` | 453 | detection | Keep · Group? |
| `detection_anomaly_threshold` | `float` | `3.0` | 460 | detection | Keep · Group? |
| `detection_slow_pattern_threshold` | `float` | `0.1` | 467 | detection | Keep · Group? |
| `detection_monitor_history_size` | `int` | `1000` | 474 | detection | Keep · Group? |
| `detection_max_tracked_patterns` | `int` | `1000` | 481 | detection | Keep · Group? |
| `enabled_detection_categories` | `set[str]` | `ALL_DETECTION_CATEGORIES` | 566 | detection | Keep |
| `excluded_detection_headers` | `set[str]` | `set` | 547 | detection (excl.) | Keep |
| `excluded_detection_params` | `set[str]` | `set` | 554 | detection (excl.) | Keep |
| `excluded_detection_body_fields` | `set[str]` | `set` | 560 | detection (excl.) | Keep |
| `enable_penetration_detection` | `bool` | `True` | 299 | detection | Keep |
| `enable_dynamic_rules` | `bool` | `False` | 405 | dynamic-rules | Keep |
| `dynamic_rule_interval` | `int` | `300` | 409 | dynamic-rules | Keep |
| `emergency_mode` | `bool` | `False` | 420 | dynamic-rules | Keep |
| `emergency_whitelist` | `list[str]` | `list` | 424 | dynamic-rules | Keep |
| `endpoint_rate_limits` | `dict[str, tuple[int, int]]` | `dict` | 429 | dynamic-rules | Keep |
| `enable_enrichment` | `bool` | `False` | 536 | enrichment | Keep |
| `ipinfo_token` | `str \| None` | `None` | 313 | ipinfo | **Deprecate (warns)** |
| `ipinfo_db_path` | `Path \| None` | `Path("data/ipinfo/country_asn.mmdb")` | 319 | ipinfo | **Deprecate (warns)** |
| `custom_log_file` | `str \| None` | `None` | 141 | logging | Keep |
| `log_suspicious_level` | `Literal[...] \| None` | `"WARNING"` | 146 | logging | Keep |
| `log_request_level` | `Literal[...] \| None` | `None` | 150 | logging | Keep |
| `log_format` | `Literal["text","json"]` | `"text"` | 154 | logging | Keep |
| `enable_logfire` | `bool` | `False` | 526 | logfire | Keep |
| `logfire_service_name` | `str` | `"guard-core"` | 531 | logfire | Keep |
| `muted_event_types` | `set[str]` | `set` | 488 | muted | Keep |
| `muted_metric_types` | `set[str]` | `set` | 493 | muted | Keep |
| `muted_check_logs` | `set[str]` | `set` | 498 | muted | Keep |
| `enable_otel` | `bool` | `False` | 503 | otel | Keep |
| `otel_service_name` | `str` | `"guard-core"` | 508 | otel | Keep · Group? |
| `otel_exporter_endpoint` | `str \| None` | `None` | 513 | otel | Keep · Group? |
| `otel_resource_attributes` | `dict[str, str]` | `dict` | 518 | otel | Keep · Group? |
| `trusted_proxies` | `list[str]` | `list` | 46 | proxy | Keep |
| `trusted_proxy_depth` | `int` | `1` | 51 | proxy | Keep |
| `trust_x_forwarded_proto` | `bool` | `False` | 56 | proxy | Keep |
| `rate_limit` | `int` | `10` | 163 | rate-limit | Keep |
| `rate_limit_window` | `int` | `60` | 167 | rate-limit | Keep |
| `enable_rate_limiting` | `bool` | `True` | 295 | rate-limit | Keep |
| `enable_redis` | `bool` | `True` | 71 | redis | Keep |
| `redis_url` | `str \| None` | `"redis://localhost:6379"` | 76 | redis | Keep |
| `redis_prefix` | `str` | `"guard_core:"` | 81 | redis | Keep |
| `security_headers` | `dict[str, Any] \| None` | headers dict | 175 | security-headers | Keep |
| `enforce_https` | `bool` | `False` | 171 | security-headers | Keep |
| `whitelist` | `list[str] \| None` | `None` | 86 | allow/deny | Keep |
| `blacklist` | `list[str]` | `list` | 95 | allow/deny | Keep |
| `blocked_user_agents` | `list[str]` | `list` | 113 | allow/deny | Keep |
| `enable_ip_banning` | `bool` | `True` | 291 | ip-banning | Keep |
| `passive_mode` | `bool` | `False` | 61 | mode | Keep |
| `custom_error_responses` | `dict[int, str]` | `dict` | 159 | hooks | Keep |
| `custom_request_check` | `Callable[...] \| None` | `None` | 194 | hooks | Keep |
| `custom_response_modifier` | `Callable[...] \| None` | `None` | 198 | hooks | Keep |
| `on_error` | `Callable[[str, BaseException, dict], None] \| None` | `None` | 342 | hooks | Keep |
| `lazy_init` | `bool` | `True` | 248 | init | Keep |
| `exclude_paths` | `list[str]` | docs/static defaults | 279 | init | Keep |
| `fail_secure` | `bool` | `True` | 303 | failure-mode | Keep |

No field is required (every field has a default or `default_factory`).

## Field counts by domain

- agent: 14
- detection (incl. 3 `excluded_detection_*` + `enable_penetration_detection`): 13
- hooks: 4 · logging: 4 · geo/country: 4 · otel: 4
- cors: 7 · dynamic-rules: 5
- auto-ban: 3 · cloud: 3 · muted: 3 · proxy: 3 · rate-limit: 3 · redis: 3 · allow/deny: 3
- security-headers: 2 · ipinfo: 2 · logfire: 2 · init: 2
- behavioral: 1 · enrichment: 1 · ip-banning: 1 · mode: 1 · failure-mode: 1

**Total: 90 fields.**

## Deprecations (wired in this audit)

`ipinfo_token` and `ipinfo_db_path` have self-described as *Deprecated* for some
time, directing users to a custom `geo_ip_handler`. They now emit a runtime
`DeprecationWarning` **when explicitly set** — the warning is raised from a
`model_validator` keyed on `model_fields_set`, so it fires once at construction
and never on internal access or when the field is left at its default.

```text
ipinfo_token is deprecated and will be removed in a future release;
create a custom geo_ip_handler instead.
```

- Non-breaking: both fields keep working; the engine still auto-builds an
  `IPInfoManager` from them when country lists are set and no `geo_ip_handler`
  is supplied (`validate_geo_ip_handler_exists`).
- Removal target: a future **major** release. Until then, migrate by passing a
  `geo_ip_handler` (any `GeoIPHandler`) directly.
- The suite filters this specific warning (`pyproject.toml` `filterwarnings`)
  so existing fixtures stay quiet; dedicated tests assert it still fires.

## Grouping opportunities

Four prefixes dominate the field count and are good candidates for **optional**
nested sub-config models (e.g. `config.agent.*`, `config.cors.*`,
`config.detection.*`, `config.otel.*`): agent (14), detection (13), cors (7),
otel (4). Presented as an option, **not applied**, because of the trade-offs:

- **For:** smaller top-level namespace; related knobs discoverable together;
  clearer typing per concern.
- **Against (breaking unless aliased):** the current flat construction
  (`SecurityConfig(agent_api_key=..., cors_allow_origins=...)`) is the documented,
  intuitive surface the design partner likes. Any grouping must ship as a
  **non-breaking additive alias layer** (accept both flat and nested, keep flat
  in `__init__` signatures) or it breaks every existing call site.

Recommendation: defer. If pursued, do it as an additive alias layer behind its
own change with a migration note, never as a silent restructure.

## Exports

`guard_core/__init__.py` `__all__` (22): `SecurityConfig`, `SecurityDecorator`,
`RouteConfig`, `BehaviorTracker`, `BehaviorRule`, `ip_ban_manager`,
`IPBanManager`, `cloud_handler`, `CloudManager`, `IPInfoManager`,
`rate_limit_handler`, `RateLimitManager`, `redis_handler`, `RedisManager`,
`security_headers_manager`, `SecurityHeadersManager`, `sus_patterns_handler`,
`GeoIPHandler`, `RedisHandlerProtocol`, `GuardRequest`, `GuardResponse`,
`GuardResponseFactory`.

`fastapi-guard/guard/__init__.py` `__all__` (24): the 22 above + the
fastapi-guard-only `SecurityMiddleware` and `__version__`.

**Drift status: none today** — the two lists agree (24 = 22 + 2). The risk is
future drift, because fastapi-guard hand-duplicates the 22 names. Single source
of truth: fastapi-guard derives its `__all__` from `guard_core.__all__` plus its
two locals, and a test asserts every exported name is importable, so a new
guard-core export can't silently go missing downstream. `IPInfoManager` stays
exported even though `ipinfo_*` config is deprecated — custom `geo_ip_handler`
implementations may still construct it directly.

## Validators & methods (reference)

`validate_ip_lists` (574) · `validate_trusted_proxies` (592) ·
`validate_proxy_depth` (610) · `coerce_country_set` (616) ·
`validate_cloud_providers` (626) · `validate_geo_ip_handler_exists` (632) ·
`validate_agent_config` (651) · `warn_deprecated_fields` (672, this audit) ·
`validate_muted_event_types` · `validate_muted_metric_types` ·
`validate_enabled_detection_categories` · `validate_threat_ban_config` ·
`validate_muted_check_logs` · `to_agent_config` (method).
