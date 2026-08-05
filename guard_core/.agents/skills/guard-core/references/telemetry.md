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

## Logfire + Pydantic: the deferred mute (postmortem)

A host app calling `logfire.instrument_pydantic()` instruments every Pydantic model validation. guard-core's telemetry models live in the `guard-agent` package (`SecurityEvent`, `SecurityMetric`, `EventBatch`). `SecurityEvent` is validated per request, and `EventBatch` re-validates every buffered event on each flush, so an instrumented host would otherwise emit one span per security-event validation — hundreds of thousands a day under real traffic (a real production postmortem measured ~384k spans/day of pure guard-event validation noise).

guard-core prevents this the first time it actually starts using guard-agent's telemetry models, not at `import guard_core`. Importing `guard_agent.models` pulls in `guard_agent.client`, `guard_agent.transport`, `guard_agent.encryption`, and `cryptography`; running the mute unconditionally at import cost every process roughly 250ms even when `enable_agent`, `enable_otel`, and `enable_logfire` were all off.

This is enforced by construction, not by auditing every construction site. No module in `guard_core/` imports `SecurityEvent`, `SecurityMetric`, or `EventBatch` from `guard_agent` directly — every one of them, including per-request paths in the event bus, the decorators, the detection engine, rate limiting, IP banning, dynamic rules, behavior tracking, Redis, cloud-provider blocking, geo-IP, and security headers, calls `guard_core._pydantic_plugin_mute.get_telemetry_model(name)`, which runs the mute and only then returns the class. `tests/test_telemetry_model_access.py` walks the AST of every file in `guard_core/` (the sync tree is generated from it, so it is the one source of truth) and fails the build if any module other than `_pydantic_plugin_mute.py` itself imports one of the three names from `guard_agent` — the property holds because a new construction site literally cannot skip the accessor without failing that test, not because someone re-audited eighteen call graphs.

`guard_core._pydantic_plugin_mute._mute_pydantic_plugin_instrumentation()` is the idempotent primitive underneath — the first call in a process does the work, every later call is a no-op. `get_telemetry_model()` calls it before every model access. `SecurityConfig.to_agent_config()` (the `enable_agent=True` path) and `HandlerInitializer.initialize_agent_integrations()` (the `enable_otel`/`enable_logfire`/`enable_enrichment` path, which can build a telemetry-capable `CompositeAgentHandler` with no agent at all) also call it directly, since they are the two points a configuration first needs `guard_agent` to exist at all, ahead of any model construction. The mute itself imports the three guard-agent models, sets `model.model_config["plugin_settings"]["logfire"] = {"record": "off"}` on each, and calls `model.model_rebuild(force=True)` (plugin_settings is only read while building a validator, so the rebuild is required). It is wrapped in try/except and silently no-ops if `guard_agent` is not installed or the mutation fails (with a warning log).

Verified behavior on the installed package:

* After `import guard_core` alone: `SecurityEvent.model_config.get("plugin_settings")` is still `None`, and `guard_agent` is not in `sys.modules`.
* After a configuration that actually turns on `enable_agent`, `enable_otel`, or `enable_logfire` initializes: it is `{'logfire': {'record': 'off'}}` for all three models.

Implication for consumers: you do not need to add `plugin_settings` to anything, as long as guard-core's own `SecurityConfig` is what turns telemetry on — you do not need to import guard-core ahead of time for this to work, since the mute rides along with the configuration that first needs it. The guard-core models themselves (`SecurityConfig` etc.) do not carry `plugin_settings`; only the guard-agent telemetry models do, and guard-core mutates them on your behalf once telemetry is configured. **Caveat:** the guarantee is that every guard-core code path is covered, by construction, not that every possible use of `guard_agent` is. If you (or another library) construct `SecurityEvent`/`SecurityMetric`/`EventBatch` through a path that never goes through a guard-core `SecurityConfig` — calling `guard_agent` directly without ever enabling `enable_agent`/`enable_otel`/`enable_logfire` on a guard-core config, for instance — that construction is not covered; call the mute yourself or set `plugin_settings` on those three models directly.
