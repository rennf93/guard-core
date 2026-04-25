Changelog
=========

All notable changes to this project will be documented in this file.

___

v2.0.0 (2026-04-25)
-------------------

Operator-facing security controls and pluggable IP lifecycle (v2.0.0)
---------------------------------------------------------------------

### Highlights

- **Detection exclusion knobs** — global and per-route opt-out for headers, query params, and JSON body fields, plus per-category disablement for the 16 known threat categories (XSS, SQLi, dir traversal, cmd injection, …). The detection engine itself is unchanged (regex set + bag-of-words token-overlap scorer); this release adds operator-facing controls on top of it.
- **`DetectionResult` replaces `tuple[bool, str]`.** Both `detect_penetration_attempt()` and `detect_penetration_patterns()` now return a dataclass carrying `is_threat`, `trigger_info`, `threat_categories`, and `threat_scores`. Callers that unpacked the tuple must migrate.
- **Per-category ban thresholds and durations.** New `ThreatBanConfig(threshold, duration)` model and `SecurityConfig.threat_ban_config: dict[str, ThreatBanConfig]`. The check increments per-category counts; the first category that crosses its own threshold short-circuits the flat-threshold fallback. Reasons are tagged `"penetration_attempt:<category>"` for category bans and `"penetration_attempt"` for flat fallback.
- **Global behavior rules.** `SecurityConfig.global_behavior_rules: list[BehaviorRuleConfig]` lets users configure 404-noise correlation and other behavioural patterns without decorators. When `correlate_with_detection=True` and the IP has any positive entry in `suspicious_request_counts`, the rule's effective threshold is halved (floor 1).
- **Lazy IP lifecycle + pluggable cloud-IP store.** `SecurityConfig.lazy_init=True` defers IPInfo MMDB download and cloud-IP fetches until the first request. `SecurityConfig.cloud_ip_store` accepts a `CloudIpStoreProtocol`; default is in-memory, automatically upgraded to Redis-backed when Redis is wired. Horizontally-scaled deployments can pre-populate the store and skip per-instance cold starts.
- **Strict protocol typing.** `redis_handler` and `agent_handler` parameters in `IPInfoManager` and `CloudManager` are typed against `RedisHandlerProtocol` / `AgentHandlerProtocol` instead of `Any`.
- **Test posture.** 3124 tests, 100% line + 100% branch coverage on every touched file, zero pytest warnings, vulture clean (10 pre-existing findings fixed at the root), pre-commit chain (ruff, mypy, vulture, bandit, radon, xenon, deptry) all green.

### Added

- `DetectionResult` dataclass at `guard_core.detection_result` (sync mirror under `guard_core.sync.detection_result`).
- `ALL_DETECTION_CATEGORIES` (frozenset of 16 labels) and `CATEGORY_CONTEXT_MAP` in `guard_core.handlers.suspatterns_handler`.
- `SecurityConfig` fields: `excluded_detection_headers`, `excluded_detection_params`, `excluded_detection_body_fields`, `enabled_detection_categories` (default = full `ALL_DETECTION_CATEGORIES` set; rejects unknown labels).
- `RouteConfig` override fields for the four detection-exclusion knobs (default `None` = inherit from `SecurityConfig`).
- `ContentFilteringMixin.detection_exclusion(headers=, params=, body_fields=, categories=)` decorator; `None` args leave the corresponding `RouteConfig` field unchanged.
- `ThreatBanConfig(threshold, duration)` model + `SecurityConfig.threat_ban_config`. Validator rejects unknown categories.
- `BehaviorRule.ban_duration: int | None` (consumed by `_execute_ban_action`, defaults to 3600 when unset). `BehaviorRule.correlate_with_detection: bool = False`.
- `BehaviorTracker.track_return_pattern(..., effective_threshold=)` override.
- `BehaviorRuleConfig` model + `SecurityConfig.global_behavior_rules: list[BehaviorRuleConfig]`. Module-level `config_to_rule(cfg) -> BehaviorRule` helper.
- `BehavioralContext.middleware: Any = None` field. `BehavioralProcessor.process_global_return_rules()` uses the existing `_behavior_tracker()` precedence helper (context tracker first, decorator tracker fallback) and short-circuits cleanly when neither is reachable.
- `ErrorResponseFactory.process_response()` accepts an optional `process_global_behavioral_rules` callback and runs it alongside the existing route-specific path. `client_ip` is extracted once and shared across both paths.
- `SecurityConfig.lazy_init: bool = False`.
- `SecurityConfig.geo_ip_db_max_age: int = 86400` (validated 3600 ≤ x ≤ 604800).
- `SecurityConfig.cloud_ip_store: CloudIpStoreProtocol | None = None`.
- `GeoIPHandler` protocol gained async `refresh()` and sync `close()`.
- `IPInfoManager(token, db_path, max_age=...)` with a `refresh()` method. `_max_age` replaces the hardcoded 86400 in disk-freshness checks and Redis TTL writes.
- `CloudIpStoreProtocol` (and `SyncCloudIpStoreProtocol` mirror) with `get` / `set` / `clear` methods.
- `InMemoryCloudIpStore` and `RedisCloudIpStore` default implementations under `guard_core.handlers.cloud_ip_stores`.
- `CloudManager.set_store()`. `refresh_async()` reads from the store first, falls back to API fetch + write-back. Legacy `redis_handler`-only path preserved when `_store is None`.
- `HandlerInitializer.initialize_redis_handlers()` wires `cloud_handler.set_store(config.cloud_ip_store)` after Redis bootstrap when an explicit store is configured. Cloud + geo bootstrap now skipped when `lazy_init=True`; `CloudIpRefreshCheck` triggers a one-shot init on the first request that needs cloud data.

### Changed

- **`detect_penetration_attempt(request, config=None, route_config=None)` → `DetectionResult`** instead of `tuple[bool, str]`.
- **`detect_penetration_patterns(...)` → `DetectionResult`** instead of `tuple[bool, str]`.
- **`GuardMiddlewareProtocol.suspicious_request_counts: dict[str, dict[str, int]]`** (was `dict[str, int]`). IP → category → count. Existing total-count semantics preserved via `sum(values())` everywhere they were read.
- **`SusPatternsManager.compiled_patterns` and `_pattern_definitions`** entries are 3-tuples `(regex, contexts, category)` (were 2-tuples). Every regex threat dict returned by `_check_regex_pattern()` now carries `category`. Custom patterns are tagged `"custom"` and bypass `enabled_categories` filtering.
- **`SusPatternsManager.detect()` and `_check_regex_patterns()`** accept an `enabled_categories: set[str] | None = None` filter.
- **`_check_value_enhanced()` / `_check_request_component()`** now return `tuple[bool, str, list[dict]]` (added the raw threats list so the public detector can extract categories and scores).
- **Cloud-IP cache Redis namespace** moved from `cloud_ranges` (comma-separated values) to `guard:cloud_ip` (JSON-encoded sorted list). See *Compat notes* below.

### Fixed

- **`setup_custom_logging`** now closes each handler before removing it, instead of relying on `logger.handlers.clear()`. Closes a `ResourceWarning` for `_io.FileIO` that surfaced under `pytest -W error::ResourceWarning`.
- **Vulture clean.** Removed 10 pre-existing dead-code findings: `scheme` parameter on `GuardRequest.url_replace_scheme` is now whitelisted (Protocol method body is `...`; renaming would break callers passing the kwarg by name); the four `unreachable code after raise` findings in `tests/test_handlers_integration.py` (and sync mirrors) replaced their `@asynccontextmanager` mocks with class-based async/sync context managers that don't need a structurally-required dead `yield`.
- **Pydantic mypy plugin** is now wired (`plugins = ["pydantic.mypy"]` in `[tool.mypy]`). Removed 10 obsolete `# type: ignore` markers and 2 stale `# TODO: Add type hints to the decorator` comments above `@field_validator` / `@model_validator` decorators in `guard_core/models.py`. Also dropped the now-unneeded `[[tool.mypy.overrides]] module = "pydantic.*" follow_imports = "skip"` block that was masking the plugin.
- **`unasync.py`** gained a multi-line `from tests.conftest import (...)` rewrite rule and a substitution rule for the new `cloud_ip_store_protocol` import path. The sync mirror now correctly renames `CloudIpStoreProtocol` → `SyncCloudIpStoreProtocol`, matching the project's `Sync*`-prefix convention for sync protocols.

### BREAKING

1. **`detect_penetration_attempt()` and `detect_penetration_patterns()` return `DetectionResult`**. Tuple-unpacking callers must migrate:

    ```python
    # Before
    detected, trigger = await detect_penetration_attempt(request)
    # After
    result = await detect_penetration_attempt(request)
    detected, trigger = result.is_threat, result.trigger_info
    # Or read result.threat_categories / result.threat_scores for richer info.
    ```

2. **`GuardMiddlewareProtocol.suspicious_request_counts: dict[str, dict[str, int]]`**. Code that reads or writes this attribute must use the nested-dict shape:

    ```python
    # Before
    self.suspicious_request_counts[ip] += 1
    # After (per-category increment)
    self.suspicious_request_counts.setdefault(ip, {})
    self.suspicious_request_counts[ip][category] = self.suspicious_request_counts[ip].get(category, 0) + 1
    # Reading the total
    total = sum(self.suspicious_request_counts.get(ip, {}).values())
    ```

3. **`SusPatternsManager` compiled-pattern tuples are 3-tuples.** `get_all_compiled_patterns()` returns `tuple[Pattern, frozenset[str], str]` instead of `tuple[Pattern, frozenset[str]]`. Direct callers that iterate this collection must unpack three elements.

4. **`_check_value_enhanced` / `_check_request_component` return 3-tuples.** External callers (none in the framework adapters; flagged here in case downstream code reaches in).

5. **Cloud-IP cache namespace migration: `cloud_ranges` → `guard:cloud_ip`.** Any ops tooling or dashboards reading those Redis keys directly must switch over. The new format is JSON-encoded sorted list of CIDRs per provider, written under namespace `guard:cloud_ip`. The legacy comma-separated path is still reachable for users who explicitly set `_store = None` on the `CloudManager` singleton, but the default and the `RedisCloudIpStore` wiring use the new namespace.

### Compat notes

- All four framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) need a release pinning `guard-core>=2.0.0` and a small migration: any adapter middleware that read `suspicious_request_counts[ip]` as an int must read `sum(suspicious_request_counts[ip].values())` (the protocol now reflects the per-category shape). Adapters that called `detect_penetration_attempt`/`detect_penetration_patterns` and unpacked the 2-tuple must consume `DetectionResult.is_threat` / `.trigger_info`.
- `lazy_init=False` is the default and preserves existing eager startup. Existing deployments do not need to opt in.
- `enabled_detection_categories` defaults to the full `ALL_DETECTION_CATEGORIES` set, so detection coverage is unchanged unless the user explicitly narrows it.
- `threat_ban_config` defaults to an empty dict and falls back to the existing `auto_ban_threshold` / `auto_ban_duration` flat behaviour — existing configurations behave identically until per-category entries are added.
- Pydantic mypy plugin was a typing tooling change; it does not affect runtime behaviour or installed dependencies.

### Tooling

- `make sync` (powered by `scripts/unasync.py`) regenerates the entire `guard_core/sync/**` tree plus matching `tests/test_sync/**`. Hand-edits are limited to files in `unasync.py:TEMPLATE_FILES` (a few sync protocol files); everything else is regenerated and verified via `python scripts/unasync.py --check` in pre-commit.
- `tests/conftest.py` `redis_cleanup` fixture now teardowns Redis state after `yield` in addition to before it. Removes a previously-hidden test-order dependency that surfaced when running tests across many invocations.

___

v1.2.1 (2026-04-24)
-------------------

Integration fixes caught by end-to-end smoke test (v1.2.1)
-----------------------------------------------------------

### Fixed

- `OtelHandler.start()` now normalizes the configured `otel_exporter_endpoint` by appending `/v1/traces` and `/v1/metrics` when the base URL lacks the signal path. Previously, users who set `otel_exporter_endpoint="http://collector:4318"` received 404 Not Found from every OTLP receiver. Matches the semantics of the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable. Also correctly rewrites explicit signal suffixes (`/v1/traces`, `/v1/metrics`, `/v1/logs`) so the traces exporter always gets `/v1/traces` and the metrics exporter always gets `/v1/metrics` regardless of which signal-specific path the user configured.
- `HandlerInitializer.build_enricher()` now owns a `BehaviorTracker` instance when the user's `SecurityDecorator` does not supply one, and caches it as `HandlerInitializer.behavior_tracker` for reuse. Without this fix, `guard.behavior.correlation_key` and `guard.behavior.recent_event_count` never populated for adapters that instantiate the middleware and decorator separately (all four current adapters).
- `BehavioralContext` gained an optional `behavior_tracker` field and `BehavioralProcessor` now threads writes through `context.behavior_tracker` when present, falling back to `guard_decorator.behavior_tracker` otherwise. This closes the architectural gap where the enricher read from one tracker while writes went to another — `guard.behavior.recent_event_count` now populates end-to-end when adapters thread the `HandlerInitializer.behavior_tracker` through their `BehavioralContext` construction (shipping in the next adapter releases).

### Compat notes

- No public API changes. `OtelHandler._otlp_signal_endpoint` is an internal helper. `BehavioralContext.behavior_tracker` has a default of `None` so existing callers continue to work unchanged.
- Adapters should bump their `guard-core>=1.2.1` pin to pick up all three fixes. See the matching `fastapi-guard 5.1.1`, `flaskapi-guard`, `djapi-guard`, `tornadoapi-guard` releases — those ship the adapter-side threading changes that complete the behaviour-correlation wiring.

___

v1.2.0 (2026-04-24)
-------------------

Enriched telemetry: client-side EventEnricher gated on guard-agent (v1.2.0)
--------------------------------------------------------------------------

### Highlights

- **Two-tier telemetry model.** Raw OTel/Logfire signal stays free and unchanged. A new **enriched** tier — gated on `enable_agent=True` + `enable_enrichment=True` — adds project identity, deterministic threat scores, dynamic-rule correlation, and per-IP behavioural correlation to every event and metric the composite fans out. Every exporter (guard-agent, OTel, Logfire) sees the same enriched payload.
- **`EventEnricher`.** New `guard_core.core.events.enricher.EventEnricher` + `EnrichmentContext` run inside `CompositeAgentHandler.send_event` / `.send_metric` between the mute filter and fan-out. Four independent strategies, each fails soft — a faulty strategy never blocks emission. Async + sync mirror parity maintained via `scripts/unasync.py`.
- **Eight `guard.*` enrichment keys.** `guard.project_id`, `guard.service.name`, `guard.deployment.environment`, `guard.threat_score`, `guard.rule.id`, `guard.rule.version`, `guard.behavior.correlation_key`, `guard.behavior.recent_event_count`. All nullable, all absent unless the corresponding context exists.
- **Deterministic threat score.** `ThreatScorer.score_for(event_type)` maps 16 event types to 0-100 scores that match the SaaS's `EVENT_SEVERITY` (`penetration_attempt=90`, `ip_banned=70`, medium events=50, `rate_limited=20`, default=20). No ML, no server-side recomputation.
- **Dynamic-rule correlation.** `DynamicRuleManager.match_event(event)` checks the cached rule against the event's IP / country / event-type and returns `(rule_id, version) | None`. The enricher attaches both keys when matched.
- **Behavioural correlation key.** 16-char SHA-256 prefix of `ip | service | floor(now/300)`, stable within a 5-minute rolling window. Combined with a new `BehaviorTracker.get_recent_event_count(ip, window)` that aggregates in-memory usage counters, dashboards can group correlated attack chains by IP.
- **OTel + Logfire forward `guard.*` metadata as span attributes.** `OtelHandler.send_event` and `LogfireHandler.send_event` now walk `event.metadata` and attach every `guard.*` key (except `traceparent` / `tracestate`, which are still used for parent-context extraction only).
- **100% line + branch coverage.** 2751 tests passing, zero skips, zero `# pragma: no cover`.

### Added

- `guard_core.core.events.enricher.EventEnricher` + `EnrichmentContext` dataclass (sync mirror under `guard_core/sync/`).
- `guard_core.core.events.enricher.ThreatScorer.score_for(event_type)` + deterministic `_THREAT_SCORE_MAP`.
- Eight `ENRICHMENT_KEY_*` constants in `guard_core.core.events.event_types` (async + sync).
- `SecurityConfig.enable_enrichment: bool` field with a `validate_agent_config` model validator that raises `ValidationError` when enrichment is requested without `enable_agent=True`.
- `HandlerInitializer.build_enricher()` factory. `build_composite_handler()` now passes the enricher into `CompositeAgentHandler`; `shutdown_agent_integrations()` clears the enricher reference. The early-exit guard in `initialize_agent_integrations` now accounts for `enable_enrichment`.
- `CompositeAgentHandler(..., enricher=...)` parameter; `send_event` / `send_metric` invoke the enricher between the mute filter and handler fan-out.
- `DynamicRuleManager.match_event(event) -> tuple[str, int] | None` returning `(rule_id, version)` when the cached rule matches.
- `BehaviorTracker.get_recent_event_count(ip, window_seconds) -> int` aggregating usage counts across all endpoints for the given IP.
- `OtelHandler.send_event` + `LogfireHandler.send_event` forward `guard.*` metadata keys as span attributes.

### Docs

- `docs/architecture/telemetry.md` updated with: the two-tier model table, the new `enable_enrichment` config field, an enrichment-fields reference table, a dedicated "Enabling enrichment" section, documentation of dynamic-rule correlation matching, and documentation of the behavioural correlation key algorithm.

### Compat notes

- All new fields / layers are strictly additive. Existing configurations with `enable_otel=True` and/or `enable_logfire=True` continue to emit raw signal unchanged.
- Adapters built against 1.1.0 continue to work against 1.2.0 without code changes — the enricher only activates when `enable_enrichment=True`, and that flag is False by default.

___

v1.1.0 (2026-04-24)
-------------------

Telemetry v1: OpenTelemetry, Logfire, and composable muting (v1.1.0)
--------------------------------------------------------------------

### Highlights

- **OpenTelemetry export** — opt-in via `enable_otel=True`. Emits guard events as spans and request metrics as OTLP-compatible instruments (`guard.request.duration`, `guard.request.count`, `guard.error.count`). Includes `otel_service_name`, `otel_exporter_endpoint`, and `otel_resource_attributes` for deployment/env/version tagging. Requires the `guard-core[otel]` extra.
- **Logfire export** — opt-in via `enable_logfire=True`. Events as `logfire.span("guard.event.<type>", ...)`, metrics as structured `logfire.info` calls. Requires the `guard-core[logfire]` extra.
- **W3C trace-context propagation** — incoming `traceparent` and `tracestate` headers are forwarded so guard spans become children of the caller's trace across the whole request lifecycle.
- **Composable muting at three layers** — `muted_event_types`, `muted_metric_types`, and `muted_check_logs` on `SecurityConfig`. Applied inside `CompositeAgentHandler` so every exporter (guard-agent, OTel, Logfire) sees the same mute rules. `muted_check_logs` also suppresses in-check `log_activity()` output, not just the pipeline logs.
- **`CompositeAgentHandler` + `EventFilter`** — every telemetry exporter runs through one handler chain with a shared filter, so new exporters get muting / propagation for free.
- **Factory methods for adapters** — `HandlerInitializer.build_event_bus()` and `.build_metrics_collector()` so framework adapters route through the composite instead of constructing `SecurityEventBus` / `MetricsCollector` directly. See *Adapter upgrade notes* below.
- **Validated mute values** — `muted_event_types`, `muted_metric_types`, and `muted_check_logs` all validate at config time against `EVENT_TYPE_VALUES` / `METRIC_TYPE_VALUES` / `CHECK_NAME_VALUES`. Typos raise `ValidationError` with the full set of valid values in the message.
- **Idempotent handler lifecycle** — `OtelHandler` / `LogfireHandler` `start()` / `stop()` are safe to call repeatedly; `stop()` nulls provider references so subsequent calls don't double-shutdown.
- **100% line + branch coverage** on every module touched (2597 tests, zero skips, zero `# pragma: no cover`).

### Added

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

### Fixed

- `logfire.metric(...)` never existed — replaced with `logfire.info("guard.metric.<type>", ...)` for structured metric logs.
- `send_metric` now warns (once per unknown type) instead of silently dropping when handed a metric_type outside `METRIC_TYPE_VALUES`.
- `OtelHandler.stop()` is now idempotent (nulls `_tracer` / `_meter`) so shutdown hooks can call it safely on re-entry.
- Sync mirror under `guard_core/sync/` fully covers every async change (behavior, decorators, detection engine, handlers, checks, events, initialization, responses, routing, validation, bypass, behavioral).

### Adapter upgrade notes

Framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) **must** switch from constructing `SecurityEventBus(agent_handler, ...)` / `MetricsCollector(agent_handler, ...)` directly to calling `initializer.build_event_bus()` / `initializer.build_metrics_collector()` *after* `initializer.initialize_agent_integrations()`. Direct construction routes events to the bare agent handler and bypasses the composite entirely — meaning OTel, Logfire, and the event filter never see pipeline-level events or request metrics. Each adapter will publish a matching minor version pinning `guard-core>=1.1.0,<2.0.0` with this wiring fix.

### Docs

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
