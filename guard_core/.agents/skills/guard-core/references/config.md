# SecurityConfig Reference

`SecurityConfig` is the single Pydantic model controlling all behavior. The installed model is the source of truth; introspect it for the exact field list, types, defaults, and descriptions.

```python
python -c "from guard_core.models import SecurityConfig; \
import json; print(json.dumps({f: {'default': SecurityConfig.model_fields[f].default, 'description': SecurityConfig.model_fields[f].description} for f in SecurityConfig.model_fields}, indent=2, default=str))"
```

## Grouped surface

### IP / geo

`whitelist`, `blacklist` (list of IPs/CIDRs), `blocked_countries`, `allowed_countries`, `whitelist_countries` (warning when both `whitelist_countries` and `blocked_countries` are set), `block_cloud_providers` (`set["AWS"|"GCP"|"Azure"]`), `geo_ip_handler` (`GeoIPHandler | None`), `ipinfo_token` (deprecated, use `geo_ip_handler`), `trusted_proxies`, `trusted_proxy_depth`, `trust_x_forwarded_proto`.

### Rate limiting / bans

`rate_limit`, `rate_limit_window`, `rate_limit_exempt`, `auto_ban_threshold`, `auto_ban_duration`, `threat_ban` (`ThreatBanConfig`), `ban_duration`, `enable_rate_limit_response_headers`.

### Detection

`detection_max_content_length` (default 10000), `detection_compiler_timeout` (default 5.0s), `detection_validation_timeout` (default 1.0s), `detection_max_pattern_length`, `detection_threat_score_threshold`, `detection_enabled_categories` (subset of the 18), `enable_dynamic_rules`.

### Redis

`enable_redis` (default `True`), `redis_url` (default `redis://localhost:6379`), `redis_prefix` (default `guard_core:`), `redis_socket_connect_timeout` (default 2.0, must be positive, 0 is non-blocking not disabled), `redis_socket_timeout` (default 2.0), `redis_health_check_interval` (default 30), `redis_max_connections`, `redis_failopen` (default `False`; on Redis errors, block rather than fall open).

### Telemetry

`enable_agent`, `agent_api_key` (required when `enable_agent=True`), `agent_endpoint`, `agent_project_id`, `agent_buffer_size`, `agent_flush_interval`, `agent_status_interval`, `agent_enable_events`, `agent_enable_metrics`, `agent_timeout`, `agent_retry_attempts`, `agent_project_encryption_key`, `agent_guard_version`, `agent_strict`, `enable_enrichment` (requires `enable_agent=True`), `enable_otel`, `otel_service_name`, `otel_exporter_endpoint`, `otel_resource_attributes`, `enable_logfire`, `logfire_service_name`.

`to_agent_config()` builds an `AgentConfig` from the agent fields when `enable_agent=True` and `agent_api_key` is set, else returns `None`.

### Pipeline behavior

`passive_mode` (log only, no block), `fail_secure` (default `True`; block 500 on check exception vs continue), `enforce_https`, `required_headers`, `blocked_user_agents`, `allowed_user_agents`, `block_empty_user_agents`, `max_request_size`, `block_if_body_too_large`, `custom_validators`, `custom_request_checks`, `time_windows`, `referrer_policy`, `enable_security_headers`, `security_headers`, `cors`, `behavior_rules` (list of `BehaviorRuleConfig`).

### Mute sets

`muted_event_types`, `muted_metric_types`, `muted_check_logs`. Validated sets; unknown values raise `ValidationError` listing valid values. See the telemetry reference for the valid value lists.

## Validation hooks

`validate_agent_config` raises `ValueError` if `enable_agent=True` but `agent_api_key` is missing. `enable_enrichment=True` without `enable_agent=True` raises `ValidationError`. Country-list conflicts emit a warning (not an error) when both `whitelist_countries` and `blocked_countries` are set.