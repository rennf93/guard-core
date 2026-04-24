Changelog
=========

All notable changes to this project will be documented in this file.

___

v1.1.0 (2026-04-24)
-------------------

Telemetry v1: OpenTelemetry, Logfire, and composable muting (v1.1.0)
--------------------------------------------------------------------

**Highlights**

- **OpenTelemetry export** — opt-in via `enable_otel=True`. Emits guard events as spans and request metrics as OTLP-compatible instruments (`guard.request.duration`, `guard.request.count`, `guard.error.count`). Includes `otel_service_name`, `otel_exporter_endpoint`, and `otel_resource_attributes` for deployment/env/version tagging. Requires the `guard-core[otel]` extra.
- **Logfire export** — opt-in via `enable_logfire=True`. Events as `logfire.span("guard.event.<type>", ...)`, metrics as structured `logfire.info` calls. Requires the `guard-core[logfire]` extra.
- **W3C trace-context propagation** — incoming `traceparent` and `tracestate` headers are forwarded so guard spans become children of the caller's trace across the whole request lifecycle.
- **Composable muting at three layers** — `muted_event_types`, `muted_metric_types`, and `muted_check_logs` on `SecurityConfig`. Applied inside `CompositeAgentHandler` so every exporter (guard-agent, OTel, Logfire) sees the same mute rules. `muted_check_logs` also suppresses in-check `log_activity()` output, not just the pipeline logs.
- **`CompositeAgentHandler` + `EventFilter`** — every telemetry exporter runs through one handler chain with a shared filter, so new exporters get muting / propagation for free.
- **Factory methods for adapters** — `HandlerInitializer.build_event_bus()` and `.build_metrics_collector()` so framework adapters route through the composite instead of constructing `SecurityEventBus` / `MetricsCollector` directly. See *Adapter upgrade notes* below.
- **Validated mute values** — `muted_event_types`, `muted_metric_types`, and `muted_check_logs` all validate at config time against `EVENT_TYPE_VALUES` / `METRIC_TYPE_VALUES` / `CHECK_NAME_VALUES`. Typos raise `ValidationError` with the full set of valid values in the message.
- **Idempotent handler lifecycle** — `OtelHandler` / `LogfireHandler` `start()` / `stop()` are safe to call repeatedly; `stop()` nulls provider references so subsequent calls don't double-shutdown.
- **100% line + branch coverage** on every module touched (2597 tests, zero skips, zero `# pragma: no cover`).

**Added**

- `SecurityConfig.muted_event_types`, `muted_metric_types`, `muted_check_logs` (validated `set[str]` fields).
- `SecurityConfig.enable_otel`, `otel_service_name`, `otel_exporter_endpoint`, `otel_resource_attributes`.
- `SecurityConfig.enable_logfire`, `logfire_service_name`.
- `guard_core.core.events.otel_handler.OtelHandler` (async + sync mirror).
- `guard_core.core.events.logfire_handler.LogfireHandler` (async + sync mirror).
- `guard_core.core.events.composite_handler.CompositeAgentHandler` — composes guard-agent + OTel + Logfire behind one `AgentHandlerProtocol`, applies `EventFilter` at fan-out.
- `guard_core.core.events.event_types.EventFilter` + `EVENT_TYPE_VALUES` / `METRIC_TYPE_VALUES` / `CHECK_NAME_VALUES` frozensets (30 / 3 / 17 members).
- `HandlerInitializer.build_event_bus()`, `.build_metrics_collector()`, `.build_composite_handler()`, `.shutdown_agent_integrations()` — factory + lifecycle API for adapters.
- `SecurityCheck.log_if_allowed()` — check-aware `log_activity` wrapper that honours `muted_check_logs`.
- `docs/architecture/telemetry.md` — full field reference, troubleshooting, and adapter wiring guidance.
- `[otel]` and `[logfire]` optional extras in `pyproject.toml`.

**Fixed**

- `logfire.metric(...)` never existed — replaced with `logfire.info("guard.metric.<type>", ...)` for structured metric logs.
- `send_metric` now warns (once per unknown type) instead of silently dropping when handed a metric_type outside `METRIC_TYPE_VALUES`.
- `OtelHandler.stop()` is now idempotent (nulls `_tracer` / `_meter`) so shutdown hooks can call it safely on re-entry.
- Sync mirror under `guard_core/sync/` fully covers every async change (behavior, decorators, detection engine, handlers, checks, events, initialization, responses, routing, validation, bypass, behavioral).

**Adapter upgrade notes**

Framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) **must** switch from constructing `SecurityEventBus(agent_handler, ...)` / `MetricsCollector(agent_handler, ...)` directly to calling `initializer.build_event_bus()` / `initializer.build_metrics_collector()` *after* `initializer.initialize_agent_integrations()`. Direct construction routes events to the bare agent handler and bypasses the composite entirely — meaning OTel, Logfire, and the event filter never see pipeline-level events or request metrics. Each adapter will publish a matching minor version pinning `guard-core>=1.1.0,<2.0.0` with this wiring fix.

**Docs**

- New `docs/architecture/telemetry.md` covering the two-tier model (raw OTel/Logfire signal; guard-agent as a parallel enriched exporter), mute field reference with all valid values, incoming `traceparent`/`tracestate` behaviour, and troubleshooting for missing spans / inactive mutes / `logfire.configure()` warnings.
- Install and extras documentation moved to uv-first tabs (`uv add "guard-core[otel]"`, then poetry, then pip) across `docs/index.md`, `docs/llms.txt`, `docs/architecture/telemetry.md`.

___

v1.0.3 (2026-04-05)
-------------------

### Added

- Guard processing time instrumentation on all request-scoped `SecurityEvent` objects via `get_pipeline_response_time()`. Covers events from `SecurityEventBus`, `SecurityCheckPipeline`, `RateLimitManager`, `BaseSecurityDecorator`, and `send_agent_event()`. Timing starts at pipeline entry and lazily initializes for events fired before or after the pipeline (bypass, behavioral). No adapter-level changes required

___

v1.0.2 (2026-04-05)
-------------------

### Fixed

- Removed `_check_ip_spoofing()` which incorrectly flagged every request with `X-Forwarded-For` headers as a spoofing attempt when `trusted_proxies` was not configured (the default)
- Added IP caching in `extract_client_ip` to avoid redundant lookups across the request lifecycle

### Added

- Guard processing time instrumentation on all request-scoped `SecurityEvent` objects via `get_pipeline_response_time()`. Covers events from `SecurityEventBus`, `SecurityCheckPipeline`, `RateLimitManager`, `BaseSecurityDecorator`, and `send_agent_event()`. Timing starts at pipeline entry and lazily initializes for events fired before or after the pipeline (bypass, behavioral). No adapter-level changes required

___

v1.0.1 (2026-03-28)
-------------------

### Fixed

- Removed false-positive suspicious patterns that blocked legitimate web traffic:
  - Static file extensions (`.html`, `.js`, `.css`, `.png`, `.jpg`, `.svg`, `.webp`, `.bmp`, `.pl`, `.properties`)
  - Common API prefixes (`/api/`, `/rest/`, `/v1/`, `/v2/`, `/status/`, `/config/`)
  - Authentication paths (`/login`, `/signin`, `/account/login`)
  - Admin paths (`/admin`)
  - Static asset directories (`/images/`, `/css/`, `/img/`, `/scripts/`)
- Retained detection for actual recon indicators: legacy server extensions (`.asp`, `.aspx`, `.jsp`, `.cfm`, `.cgi`, etc.), and suspicious management endpoints (`/management`, `/config_dump`, `/credentials`)

___

v1.0.0 (2026-03-25)
--------------------

### Added

- Complete synchronous API (`guard_core.sync`) generated via `scripts/unasync.py`, including sync versions of all 17 security checks, handlers, decorators, protocols, detection engine, and utilities
- `scripts/unasync.py` transformation tool converting async code to sync (`async def` to `def`, `await` removed, `aiohttp` to `requests`, `redis.asyncio` to `redis`, `asyncio.Lock` to `threading.Lock`)
- Sync protocols: `SyncGuardRequest`, `SyncGuardMiddlewareProtocol`, and sync versions of all handler protocols
- PEP 561 type stub markers (`guard_core/py.typed`, `guard_core/sync/py.typed`)
- Project governance files: `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`
- `README.md` with project documentation, badges, and ecosystem overview
- `.safety-project.ini` for dependency vulnerability scanning
- `MANIFEST.in` and `.gitattributes` for packaging
- `.python-version` specifying supported Python versions (3.10-3.14)
- Comprehensive edge-case test suites for cloud provider, HTTPS enforcement, IP security, rate limiting, and time window checks
- `docs/llms.txt` for LLM-assisted development context
- Complete sync test suite (`tests/test_sync/`) mirroring the async test structure

### Changed

- Restructured and consolidated the entire test suite into organized directories (`test_agent/`, `test_core/`, `test_decorators/`, `test_features/`, `test_handlers/`, etc.)
- Enhanced `CloudManager` with IP range change logging and improved provider refresh logic
- Updated `SusPatternsManager` with additional detection logic
- Enhanced `BehavioralProcessor`, `ErrorResponseFactory`, and `RouteConfigResolver` internals
- Minor updates to `IPInfoManager` handler
- Updated `BaseSecurityDecorator` route config handling
- Added mypy override for `guard_core.sync.*` (type suppression for generated sync code)
- Documentation fully standardized and verified for accuracy against source code
- Disabled safety pre-commit hook temporarily

### Fixed

- Suspicious pattern handling in `detect_penetration_attempt`

___

v0.1.0 (2026-03-23)
--------------------

### New Features (v0.1.0)

- **Initial release**: Guard Core extracted as a framework-agnostic security library for Python web applications.
- **Protocol-based architecture**: Uses `GuardRequest` and `GuardResponse` protocols for framework independence.
- **Full feature parity**: All security features available through framework-agnostic APIs.
- **IP Management**: Whitelisting, blacklisting, geolocation, cloud provider blocking.
- **Rate Limiting**: Sliding window algorithm with in-memory and Redis backends.
- **Penetration Detection**: Enhanced detection engine with pattern matching, semantic analysis, and performance monitoring.
- **Security Decorators**: Route-level security controls for access control, authentication, rate limiting, behavioral analysis, content filtering, and advanced features.
- **Security Headers**: Comprehensive HTTP security header management following OWASP best practices.
- **Redis Integration**: Distributed state management for multi-instance deployments.
- **Behavioral Analysis**: Usage monitoring, return pattern detection, and frequency analysis.
