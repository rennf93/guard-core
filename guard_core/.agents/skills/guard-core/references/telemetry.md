# Telemetry

guard-core emits security events and request metrics through a composable, two-tier pipeline. Mute works globally inside `CompositeAgentHandler.send_event` / `.send_metric`; every emission site (event bus, decorator-level, handler-level) routes through the composite when the adapter wires it via `HandlerInitializer.initialize_agent_integrations()`.

## Two tiers

| Tier | Gate | Exporters see |
|---|---|---|
| Raw | `enable_otel=True` and/or `enable_logfire=True` | All event types, all metrics, W3C `traceparent`/`tracestate` continuation, muting. No `guard.*` enrichment. |
| Enriched | `enable_agent=True` + `enable_enrichment=True` | Raw plus `guard.project_id`, `guard.service.name`, `guard.deployment.environment`, `guard.threat_score`, `guard.rule.id` + `guard.rule.version`, `guard.behavior.correlation_key` + `guard.behavior.recent_event_count`. |

`enable_enrichment=True` without `enable_agent=True` raises `ValidationError`. Enrichment is always client-side; guard-core-app's backend stores the fields as-is, no server-side computation.

## Config surface (10 fields)

| Field | Default | Purpose |
|---|---|---|
| `muted_event_types` | `set()` | Suppress these event types from every exporter. |
| `muted_metric_types` | `set()` | Suppress these metric types. |
| `muted_check_logs` | `set()` | Suppress in-check `log_activity()` output. |
| `enable_otel` | `False` | OpenTelemetry export (requires `[otel]` extra). |
| `otel_service_name` | `"guard-core"` | OTel resource service name. |
| `otel_exporter_endpoint` | `None` | OTLP/HTTP endpoint; `None` uses OTel default `localhost:4318`. |
| `otel_resource_attributes` | `{}` | Extra OTel resource attributes. A `service.name` key here overrides `otel_service_name`. |
| `enable_logfire` | `False` | Logfire export (requires `[logfire]` extra). |
| `logfire_service_name` | `"guard-core"` | Logfire service name. |
| `enable_enrichment` | `False` | Populate `guard.*` metadata. Requires `enable_agent=True`. |

## Valid mute values

From `guard_core.core.events.event_types`:

* `EVENT_TYPE_VALUES` (33): `access_denied`, `authentication_failed`, `behavior_violation`, `cloud_blocked`, `content_filtered`, `country_blocked`, `csp_violation`, `custom_request_check`, `decoding_error`, `decorator_violation`, `dynamic_rule_applied`, `dynamic_rule_updated`, `dynamic_rule_violation`, `emergency_mode_activated`, `emergency_mode_block`, `geo_lookup_failed`, `https_enforced`, `ip_banned`, `ip_blocked`, `ip_unbanned`, `path_excluded`, `pattern_added`, `pattern_detected`, `pattern_removed`, `penetration_attempt`, `rate_limited`, `rate_limit_script_reloaded`, `redis_connection`, `redis_error`, `route_unresolved`, `security_bypass`, `security_headers_applied`, `user_agent_blocked`.
* `METRIC_TYPE_VALUES` (3): `error_rate`, `request_count`, `response_time`.
* `CHECK_NAME_VALUES` (17): the pipeline order — `authentication`, `cloud_ip_refresh`, `cloud_provider`, `custom_request`, `custom_validators`, `emergency_mode`, `https_enforcement`, `ip_security`, `rate_limit`, `referrer`, `request_logging`, `request_size_content`, `required_headers`, `route_config`, `suspicious_activity`, `time_window`, `user_agent`.

## Enrichment field sources

| Key | Source |
|---|---|
| `guard.project_id` | `SecurityConfig.agent_project_id` |
| `guard.service.name` | `SecurityConfig.otel_service_name` |
| `guard.deployment.environment` | `SecurityConfig.otel_resource_attributes["deployment.environment"]` |
| `guard.threat_score` | deterministic `ThreatScorer.score_for(event_type)` map (`penetration_attempt=90`, `ip_banned=70`, medium=50, `rate_limited=20`, default=20) |
| `guard.rule.id` / `guard.rule.version` | `DynamicRuleManager.match_event` when the cached rule's IP/country/event-type matched |
| `guard.behavior.correlation_key` | `sha256` snippet below — stable within a 5-min window |
| `guard.behavior.recent_event_count` | `BehaviorTracker.get_recent_event_count(ip, 300)` — in-memory |

`guard.behavior.correlation_key` source:

```python
sha256(f"{ip}|{service}|{floor(now/300)}").hexdigest()[:16]
```

All fields are nullable and absent unless context is available.

## OTel instruments

`send_metric` emits: `guard.request.duration` (histogram, seconds), `guard.request.count` (counter), `guard.error.count` (counter). Any other metric type produces a one-line warning and is dropped.

## Logfire + Pydantic: the import-time mute (postmortem)

A host app calling `logfire.instrument_pydantic()` instruments every Pydantic model validation. guard-core's telemetry models live in the `guard-agent` package (`SecurityEvent`, `SecurityMetric`, `EventBatch`). `SecurityEvent` is validated per request, and `EventBatch` re-validates every buffered event on each flush, so an instrumented host would otherwise emit one span per security-event validation — hundreds of thousands a day under real traffic (a real production postmortem measured ~384k spans/day of pure guard-event validation noise).

guard-core prevents this at import time. `guard_core/__init__.py` runs `_mute_pydantic_plugin_instrumentation()`, which imports the three guard-agent models, sets `model.model_config["plugin_settings"]["logfire"] = {"record": "off"}` on each, and calls `model.model_rebuild(force=True)` (plugin_settings is only read while building a validator, so the rebuild is required). The function is wrapped in try/except and silently no-ops if `guard_agent` is not installed or the mutation fails (with a warning log).

Verified behavior on the installed package:

* Before `import guard_core`: `SecurityEvent.model_config.get("plugin_settings")` is `None`.
* After `import guard_core`: it is `{'logfire': {'record': 'off'}}` for all three models.

Implication for consumers: you do not need to add `plugin_settings` to anything. Importing guard-core (which your adapter does) is sufficient. The guard-core models themselves (`SecurityConfig` etc.) do not carry `plugin_settings`; only the guard-agent telemetry models do, and guard-core mutates them on your behalf. If you depend on `guard-agent` directly without going through a guard-core adapter, import guard-core once to get the mute, or set the plugin_settings yourself on those three models.
