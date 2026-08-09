# SecurityConfig Reference

`SecurityConfig` is the single Pydantic model controlling all behavior. The installed model is the source of truth; introspect it for the exact field list, types, defaults, and descriptions.

```python
python -c "from guard_core.models import SecurityConfig; \
import json; print(json.dumps({f: {'default': SecurityConfig.model_fields[f].default, 'description': SecurityConfig.model_fields[f].description} for f in SecurityConfig.model_fields}, indent=2, default=str))"
```

## Grouped surface

Field names below are verified against the installed `SecurityConfig.model_fields`; a per-route knob (set through a decorator, not `SecurityConfig`) is called out explicitly where one could be confused for a global field of the same shape.

### IP / geo

`whitelist`, `blacklist` (IPs/CIDRs; an explicit whitelist match overrides the blacklist), `blocked_countries`, `whitelist_countries` (ISO 3166-1 alpha-2; a non-empty set is restrictive -- only listed countries pass, and an unresolved country is blocked), `block_cloud_providers` (`set[str]`; bare `"GCP"` blocks the whole provider, `"GCP:!us-central1"` carves out a region for GCP/AWS), `geo_ip_handler` (`GeoIPHandler | None`), `ipinfo_token`/`ipinfo_db_path` (deprecated, create a custom `geo_ip_handler` instead), `trusted_proxies`, `trusted_proxy_depth` (default `1`), `trust_x_forwarded_proto`.

Route-level IP/country overrides (`ip_whitelist`, `ip_blacklist`, `blocked_countries`, `whitelist_countries`, `require_https`) live on `RouteConfig`, set via decorators, not on `SecurityConfig`.

### Rate limiting / bans

`rate_limit` (default `10`), `rate_limit_window` (default `60`), `auto_ban_threshold` (default `10`), `auto_ban_duration` (default `3600`), `threat_ban_config` (`dict[str, ThreatBanConfig]`; per-category threshold/duration override, unlisted categories fall back to `auto_ban_threshold`/`auto_ban_duration`), `global_behavior_rules` (list of `BehaviorRuleConfig`, applied to every route in addition to any decorator-specified rules), `enable_ip_banning` (default `True`), `enable_rate_limiting` (default `True`), `endpoint_rate_limits` (per-endpoint limits, normally set by dynamic rules).

Per-route rate limiting (`rate_limit`, `rate_limit_window`, `geo_rate_limits`) and per-route `behavior_rules` live on `RouteConfig`.

### Detection

`detection_compiler_timeout` (default `2.0`, range `0.1`-`10.0`; per-pattern match timeout), `detection_max_content_length` (default `10000`), `detection_max_body_inspect_bytes` (default `262144`), `detection_preserve_attack_patterns` (default `True`), `detection_semantic_threshold` (default `0.7`), `detection_anomaly_threshold` (default `3.0`), `detection_slow_pattern_threshold` (default `0.1`), `detection_monitor_history_size` (default `1000`), `detection_max_tracked_patterns` (default `1000`), `detection_threat_score_threshold` (default `1.0`), `detection_scan_body` (default `True`), `enabled_detection_categories` (subset of the 18; `None` means all), `enable_penetration_detection` (default `True`), `enable_dynamic_rules` (default `False`). See `docs/configuration/detection-tuning.md` in the guard-core repository for the full field-by-field tuning guide.

`PatternCompiler.validate_pattern_safety`'s own probe/wait budget (50ms soft, 1.0s hard) is a hardcoded constant, not a `SecurityConfig` field.

### Redis

`enable_redis` (default `True`), `redis_url` (default `redis://localhost:6379`), `redis_prefix` (default `guard_core:`), `redis_socket_connect_timeout` (default `2.0`), `redis_socket_timeout` (default `2.0`), `redis_health_check_interval` (default `30`), `redis_max_connections`, `redis_retries` (default `1`; retries with exponential backoff before surfacing a transient Redis error), `redis_fail_open` (default `False`; on `GuardRedisError`, skip the failing check and fall through instead of honoring `fail_secure`).

### Telemetry

`enable_agent`, `agent_api_key` (required when `enable_agent=True`), `agent_strict`, `agent_endpoint`, `agent_project_id`, `agent_buffer_size`, `agent_flush_interval`, `agent_status_interval`, `agent_enable_events`, `agent_enable_metrics`, `agent_timeout`, `agent_retry_attempts`, `agent_project_encryption_key`, `agent_guard_version`, `agent_high_watermark_ratio`, `agent_max_concurrent_flushes`, `agent_buffer_overflow_policy` (`Literal["drop", "block", "raise"] | None`, rejected at construction if set to anything else), `agent_backoff_factor`, `agent_sensitive_headers`, `agent_max_payload_size`, `agent_compression_enabled`, `agent_compression_threshold`, `agent_install_id`, `agent_payload_signing_secret`, `on_error` (also forwarded to `AgentConfig.on_error`, receiving guard-agent's `transport_send`/`encryption` failures alongside guard-core's own `agent_init`/`geoip` failures), `enable_enrichment` (requires `enable_agent=True`), `enable_otel`, `otel_service_name`, `otel_exporter_endpoint`, `otel_resource_attributes`, `enable_logfire`, `logfire_service_name`.

`to_agent_config()` builds an `AgentConfig` from the agent fields when `enable_agent=True` and `agent_api_key` is set, else returns `None`. The ten `agent_*` fields listed above with a `None` default (plus `on_error`) are each omitted from the `AgentConfig(...)` call when unset, so `AgentConfig`'s own default applies instead of a duplicated value drifting out of sync with guard-agent.

### Pipeline behavior

`passive_mode` (log only, no block), `fail_secure` (default `True`; block 500 on check exception vs continue), `enforce_https`, `security_headers` (dict: `enabled`, `hsts`, `csp`, `frame_options`, `content_type_options`, `xss_protection`, `referrer_policy`, `permissions_policy`, `custom` keys), `custom_request_check`, `custom_response_modifier`, `enable_cors`, `cors_allow_origins`, `cors_allow_methods`, `cors_allow_headers`, `cors_allow_credentials`, `cors_expose_headers`, `cors_max_age`, `exclude_paths`, `route_resolution_strict` (default `False`), `lazy_init` (default `True`), `emergency_mode`, `emergency_whitelist`.

Per-route gates -- `required_headers`, `blocked_user_agents`, `max_request_size`, `allowed_content_types`, `custom_validators`, `time_restrictions`, `require_referrer`, `auth_required`, `api_key_required` -- live on `RouteConfig`, set via decorators, not on `SecurityConfig`.

### Logging

`custom_log_file`, `log_suspicious_level` (default `WARNING`), `log_request_level` (default `None`; set to enable request logging), `log_country_check_level` (default `INFO`; non-block country verdicts, `None` silences them), `log_format` (`"text"` or `"json"`), `custom_error_responses`.

### Mute sets

`muted_event_types`, `muted_metric_types`, `muted_check_logs`. Validated sets; unknown values raise `ValidationError` listing valid values. See the telemetry reference for the valid value lists.

## Optional extras

`import guard_core` no longer loads `aiohttp`, `maxminddb`, `redis`, `guard_agent`, or `cryptography`; those load lazily, only when a check that needs them is actually built or a feature that needs them is actually configured. Three optional-dependency extras package the split: `redis` (the `redis` package, needed when `enable_redis=True`), `cloud` (`aiohttp` and `requests`, needed when `block_cloud_providers` is set or `enable_dynamic_rules=True`, since dynamic rules can turn cloud blocking on at runtime), and `geo` (`maxminddb`, needed when `blocked_countries` or `whitelist_countries` is set and no custom `geo_ip_handler` is supplied, the one case where guard-core constructs its own `IPInfoManager`). All three extras' packages are also still listed in guard-core's base `dependencies` through the 3.x line, so an existing install is unaffected; the extras exist so a deployment can be explicit about which features it needs, and they become the only source of those packages at 4.0.

`SecurityConfig`'s `validate_optional_extras_installed` model validator checks `importlib.util.find_spec` (never a bare `import`) for each configured feature and raises `ValueError` naming the missing extra's `pip install guard-core[...]` command, instead of letting the feature fail later with a raw `ImportError`. Configuring a feature whose extra is not installed fails at `SecurityConfig` construction, not mid-request.

## Validation hooks

`validate_agent_config` raises `ValueError` if `enable_agent=True` but `agent_api_key` is missing. `enable_enrichment=True` without `enable_agent=True` raises `ValidationError`. Country-list conflicts emit a warning (not an error) when both `whitelist_countries` and `blocked_countries` are set. `SecurityConfig` still allows unknown constructor keyword arguments (`extra="ignore"`, unchanged); `warn_unknown_fields` logs a `guard_core.models` warning naming each one so a typo'd field name is not silently a no-op. `extra="forbid"` is the intended behavior at a future major release; this warning is the migration runway.
