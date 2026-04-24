# Telemetry

Guard Core emits security events and request metrics through a composable telemetry pipeline. Events can be muted, metrics can be muted, individual security-check logs can be muted, and exports to OpenTelemetry and Logfire are opt-in.

## Config surface

Nine `SecurityConfig` fields control telemetry:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `muted_event_types` | `set[str]` | `set()` | Suppress these event types from every exporter. |
| `muted_metric_types` | `set[str]` | `set()` | Suppress these metric types from every exporter. |
| `muted_check_logs` | `set[str]` | `set()` | Suppress pipeline + in-check log output for these checks. |
| `enable_otel` | `bool` | `False` | Enable OpenTelemetry span/metric export (requires `[otel]` extra). |
| `otel_service_name` | `str` | `"guard-core"` | Service name for OpenTelemetry resource. |
| `otel_exporter_endpoint` | `str \| None` | `None` | OTLP/HTTP endpoint. `None` uses OTel's default (`localhost:4318`). |
| `otel_resource_attributes` | `dict[str, str]` | `{}` | Extra OpenTelemetry resource attributes (e.g. `deployment.environment`, `service.version`). |
| `enable_logfire` | `bool` | `False` | Enable Logfire export (requires `[logfire]` extra). |
| `logfire_service_name` | `str` | `"guard-core"` | Service name for Logfire. |

All three mute fields validate their contents at config time. Unknown values raise `ValidationError` and the error message lists the valid values.

Mute is applied globally inside `CompositeAgentHandler.send_event` / `.send_metric`. Every event emitted via `SecurityEventBus`, decorator-level `send_decorator_event`, or handler-level `agent_handler.send_event()` goes through the composite, so mute works uniformly regardless of emission site — as long as the adapter installs the composite through `HandlerInitializer.initialize_agent_integrations()`.

## Valid mute values

Drawn from constants in `guard_core.core.events.event_types`:

- `EVENT_TYPE_VALUES` (30 values): `access_denied`, `authentication_failed`, `behavior_violation`, `cloud_blocked`, `content_filtered`, `country_blocked`, `csp_violation`, `custom_request_check`, `decoding_error`, `decorator_violation`, `dynamic_rule_applied`, `dynamic_rule_updated`, `emergency_mode_activated`, `emergency_mode_block`, `geo_lookup_failed`, `https_enforced`, `ip_banned`, `ip_blocked`, `ip_unbanned`, `path_excluded`, `pattern_added`, `pattern_detected`, `pattern_removed`, `penetration_attempt`, `rate_limited`, `redis_connection`, `redis_error`, `security_bypass`, `security_headers_applied`, `user_agent_blocked`
- `METRIC_TYPE_VALUES`: `error_rate`, `request_count`, `response_time`
- `CHECK_NAME_VALUES`: `authentication`, `cloud_ip_refresh`, `cloud_provider`, `custom_request`, `custom_validators`, `emergency_mode`, `https_enforcement`, `ip_security`, `rate_limit`, `referrer`, `request_logging`, `request_size_content`, `required_headers`, `route_config`, `suspicious_activity`, `time_window`, `user_agent`

## Muting events, metrics, and check logs

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    muted_event_types={"penetration_attempt"},
    muted_metric_types={"response_time"},
    muted_check_logs={"rate_limit", "user_agent"},
)
```

- `muted_event_types` short-circuits `SecurityEventBus.send_middleware_event()` before the event reaches any exporter.
- `muted_metric_types` short-circuits `MetricsCollector.send_metric()` before the metric reaches any exporter.
- `muted_check_logs` suppresses both the pipeline's block/error log entries *and* the in-check `log_activity()` calls — both are gated on the same set.

## Enabling OpenTelemetry

=== "uv"

    ```bash
    uv add "guard-core[otel]"
    ```

=== "poetry"

    ```bash
    poetry add "guard-core[otel]"
    ```

=== "pip"

    ```bash
    pip install "guard-core[otel]"
    ```

```python
config = SecurityConfig(
    enable_otel=True,
    otel_service_name="guard-prod",
    otel_exporter_endpoint="http://otel-collector.internal:4318",
    otel_resource_attributes={
        "deployment.environment": "prod",
        "service.version": "1.2.0",
    },
)
```

If `otel_resource_attributes` contains a `service.name` key it overrides `otel_service_name` (last-write-wins: the extra attributes dict is applied after the service-name key is set). Prefer setting service name via `otel_service_name` and use `otel_resource_attributes` only for environment/version/region tags.

Incoming W3C `traceparent` headers are continued automatically — guard spans become children of the caller's trace. `tracestate` headers are forwarded alongside when present.

`send_metric` emits three instruments when enabled:

- `guard.request.duration` (histogram, seconds)
- `guard.request.count` (counter)
- `guard.error.count` (counter)

Any other metric type produces a one-line warning and is dropped.

## Enabling Logfire

=== "uv"

    ```bash
    uv add "guard-core[logfire]"
    ```

=== "poetry"

    ```bash
    poetry add "guard-core[logfire]"
    ```

=== "pip"

    ```bash
    pip install "guard-core[logfire]"
    ```

```python
config = SecurityConfig(
    enable_logfire=True,
    logfire_service_name="guard-prod",
)
```

Events are emitted as `logfire.span("guard.event.<event_type>", ...)` and metrics as structured logs via `logfire.info("guard.metric.<metric_type>", value=..., endpoint=..., **tags)`. When both `enable_otel` and `enable_logfire` are set, Logfire also observes the OpenTelemetry instruments automatically via its OTel bridge.

## Adapter wiring

Framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) build the event bus and metrics collector through the factory methods on `HandlerInitializer` so the composite handler and event filter are wired automatically:

```python
from guard_core.core.initialization.handler_initializer import HandlerInitializer

initializer = HandlerInitializer(
    config=config,
    redis_handler=redis_handler,
    agent_handler=agent_handler,
    geo_ip_handler=geo_handler,
    rate_limit_handler=rate_limit_handler,
    guard_decorator=decorator_handler,
)

await initializer.initialize_redis_handlers()
await initializer.initialize_agent_integrations()   # starts composite_handler

event_bus = initializer.build_event_bus(geo_ip_handler=geo_handler)
metrics_collector = initializer.build_metrics_collector()

# ... run the app ...

await initializer.shutdown_agent_integrations()     # stops composite_handler
```

`build_event_bus()` and `build_metrics_collector()` raise `RuntimeError` if called before `initialize_agent_integrations()` — the composite handler and event filter must exist first.

## Incoming `traceparent`

When `enable_otel=True` and the request carries a W3C `traceparent` header, `SecurityEventBus` copies it into the event's metadata. `OtelHandler.send_event()` extracts it with `TraceContextTextMapPropagator` and sets the resumed context as the parent of `guard.event.<event_type>` spans. This preserves the upstream trace across the guard layer.

## Troubleshooting

### Spans don't show up in your OTel backend

1. Verify `enable_otel=True` is set.
2. Check `python -c "import opentelemetry.sdk"` — if it raises `ImportError`, the handler logs `opentelemetry-sdk not installed, OTEL handler disabled` on startup.
3. Confirm `otel_exporter_endpoint` points to an OTLP/HTTP receiver on port `4318` (not `4317` — that's gRPC).
4. Confirm the adapter calls `initializer.build_event_bus()` and the middleware uses that bus (not a locally-constructed `SecurityEventBus`).

### Events aren't muted even though you set `muted_event_types`

The adapter may be constructing `SecurityEventBus(...)` directly and passing no `event_filter`. Switch it to `initializer.build_event_bus()`.

### `logfire.info()` warning: "No logs or spans will be created until `logfire.configure()` has been called"

Guard Core configures Logfire inside `LogfireHandler.start()`. This runs during `initialize_agent_integrations()`. If the warning appears after startup, the integration may not have been initialised — verify `enable_logfire=True` is set before `initialize_agent_integrations()` runs.

### Unknown check/event/metric in mute set raises `ValidationError`

The error message lists the valid values. Common typos: `"suspicious"` instead of `"suspicious_activity"`, `"latency"` instead of `"response_time"`.
