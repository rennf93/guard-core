---
name: guard-core
description: Guard Core best practices and conventions for the framework-agnostic Python security engine. Use when working with guard-core, SecurityConfig, the security check pipeline, detection engine (SusPatternsManager, PatternCompiler, ContentPreprocessor, SemanticAnalyzer), telemetry/event bus (OTel, Logfire, guard-agent enrichment), or building a framework adapter via the GuardRequest/GuardResponse/GuardResponseFactory protocols. Covers setup, the config-derived security pipeline (17-check catalogue), the 18-category detection catalog, telemetry models, and known footguns
---

# Guard Core

Official guard-core skill to write code with best practices, keeping up to date with the real installed surface (introspect the package, do not rely on model memory of it).

guard-core is the framework-agnostic security engine powering the Guard ecosystem. Framework adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard) implement three protocols and get the full pipeline, detection engine, Redis state, and telemetry for free.

## Quick Reference

* Adapter authors: implement `GuardRequest`, `GuardResponse`, `GuardResponseFactory`; see [Adapters](#building-adapters) and [the adapters reference](references/adapters.md).
* All behavior is `SecurityConfig`; do not mutate handlers directly; see [SecurityConfig](#securityconfig) and [the config reference](references/config.md).
* Detection: `SusPatternsManager.detect()` over 18 categories; see [Detection Engine](#detection-engine) and [the detection reference](references/detection.md).
* Telemetry: two tiers (raw OTel/Logfire free, guard-agent enrichment gated); see [Telemetry](#telemetry) and [the telemetry reference](references/telemetry.md).
* Logfire + Pydantic: guard-core mutes guard-agent telemetry-model instrumentation the first time a config actually enables agent/OTel/Logfire, not at `import guard_core`; see [Footguns](#footguns).
* Sync mirror: `guard_core.sync.*` is unasync-generated from `guard_core.*`; never hand-edit it; see [Sync mirror](#sync-mirror).

## Installation

```bash
pip install guard-core
# feature extras: redis, aiohttp/requests and maxminddb are still base dependencies through the 3.x line, so these are additive, not required
pip install "guard-core[redis]"     # enable_redis
pip install "guard-core[cloud]"     # block_cloud_providers / cloud-provider blocking
pip install "guard-core[geo]"       # blocked_countries / whitelist_countries when no custom geo_ip_handler is supplied
# optional telemetry extras
pip install "guard-core[otel]"      # OpenTelemetry export
pip install "guard-core[logfire]"   # Logfire export
```

`import guard_core` no longer loads `aiohttp`, `maxminddb`, `redis`, `guard_agent`, or `cryptography`; a bare import costs roughly 1.6ms. Handlers and third-party libraries load lazily, only when a check that needs them is actually built or a feature that needs them is actually configured. If a feature is configured without its extra installed, `SecurityConfig` raises a `ValueError` at construction time naming the missing extra's install command, instead of surfacing a raw `ImportError` mid-request. See [the config reference](references/config.md#optional-extras) for exactly which flags gate which extra.

`guard-agent` is an optional runtime dependency pulled in by adapters when `enable_agent=True`; it is not a hard dependency of guard-core.

## SecurityConfig

All behavior is controlled through one Pydantic model. Construct it once and pass it to your adapter's middleware/initializer.

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    whitelist=["192.168.1.0/24"],
    blacklist=["10.0.0.1"],
    blocked_countries=["CN"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    rate_limit=100,
    rate_limit_window=60,
    enforce_https=True,
    block_cloud_providers={"AWS", "GCP", "Azure"},
    enable_redis=True,
    redis_url="redis://localhost:6379",
)
```

Field defaults are the source of truth. For an authoritative list of every field, type, default, and description, introspect the installed model rather than recalling from memory:

```python
python -c "from guard_core.models import SecurityConfig; \
import json; print(json.dumps({f: (SecurityConfig.model_fields[f].default, SecurityConfig.model_fields[f].description) for f in SecurityConfig.model_fields}, indent=2, default=str))"
```

Key defaults that bite:

* `fail_secure` defaults to `True`. A check raising an unexpected exception blocks with HTTP 500 instead of falling through. Opt back into fail-open with `SecurityConfig(fail_secure=False)` only if you understand the risk.
* `enable_redis` defaults to `True` with `redis_url="redis://localhost:6379"`. If you have no Redis, set `enable_redis=False` or point at a real instance; do not leave the default running in a no-Redis environment.
* `passive_mode` defaults to `False`. Set `True` for log-only mode (no blocking, events still emit).

See [the config reference](references/config.md) for the full field surface and the telemetry/detection-tuning fields.

## Building Adapters

Implement three protocols to bridge your framework into the pipeline. Everything else (the check catalogue, detection engine, Redis state, event telemetry) works out of the box; expose `guard_decorator` on your middleware so guard-core can enumerate registered routes and build a smaller, config-derived pipeline instead of keeping every route-driven check (see [Security Pipeline](#security-pipeline)).

```python
from guard_core.protocols import GuardRequest, GuardResponse, GuardResponseFactory
```

`GuardRequest` exposes: `url_path`, `url_scheme`, `url_full`, `url_replace_scheme(scheme)`, `method`, `client_host`, `headers`, `query_params`, `async body()`, `state`, `scope`.

`GuardResponse` exposes: `status_code`, `headers`, `body`.

`GuardResponseFactory` exposes: `create_response(content, status_code)`, `create_redirect_response(url, status_code)`.

See [the adapters reference](references/adapters.md) for a complete wrapper example and the middleware-wiring checklist.

## Security Pipeline

`SecurityCheckPipeline` runs, per request, whichever checks the effective configuration can actually trigger, in the fixed catalogue order below. `build_default_pipeline` filters the 17-check catalogue through each check's `applies_to(config, route_configs)` classmethod before instantiating anything; the base `SecurityCheck.applies_to` returns `True`, so a check that does not override it always runs, and elimination is strictly an optimization, never a security decision. The catalogue and its order are unchanged; only the subset a given deployment builds varies.

1. route_config
2. emergency_mode
3. https_enforcement
4. request_logging
5. request_size_content
6. required_headers
7. authentication
8. referrer
9. custom_validators
10. time_window
11. cloud_ip_refresh
12. ip_security
13. cloud_provider
14. user_agent
15. rate_limit
16. suspicious_activity
17. custom_request

A default `SecurityConfig()` with no route decorators registered builds only `route_config`, `ip_security`, `rate_limit`, and `suspicious_activity`; a configuration that enables every feature builds all 17. `enable_dynamic_rules=True` keeps `emergency_mode`, `cloud_ip_refresh`, `cloud_provider`, `user_agent`, `rate_limit`, and `suspicious_activity` regardless of every other flag, because `DynamicRuleManager` can mutate the flags those checks key off at runtime. `ip_security` never overrides `applies_to`, so it always builds: it fronts a ban lookup whose store is writable from behavior-rule bans and from other processes sharing the same Redis, so no configuration can prove it unreachable. When the registered route configuration cannot be enumerated (`route_configs is None`), every route-driven check is kept rather than dropped, so an adapter that cannot expose `guard_decorator` loses the build-time optimization but never loses the protection. The first check returning a non-`None` `GuardResponse` short-circuits and blocks; order matters, since earlier checks set up state later checks depend on. A check returning `None` means pass. On a check exception, `fail_secure` decides block-with-500 vs continue. See [the pipeline reference](references/pipeline.md).

## Detection Engine

`guard_core.detection_engine` exposes four components, orchestrated by `SusPatternsManager` (in `guard_core.handlers.suspatterns_handler`).

```python
from guard_core.detection_engine import (
    PatternCompiler,
    ContentPreprocessor,
    SemanticAnalyzer,
    PerformanceMonitor,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.detection_result import DetectionResult
```

`SusPatternsManager.detect(content, ip_address, context="unknown", correlation_id=None, enabled_categories=None) -> dict[str, Any]` is the primary entry point. It preprocesses (up to 7 decode layers: URL, HTML entities, base64, hex, Unicode escapes, SQL comments, null-byte strip), matches ~64 regex patterns across 18 categories with context filtering, runs a multi-metric semantic score, and returns a threat dict.

The 18 detection categories (`ALL_DETECTION_CATEGORIES`): `xss`, `sqli`, `dir_traversal`, `path_traversal`, `cmd_injection`, `file_inclusion`, `ldap`, `xml`, `ssrf`, `nosql`, `file_upload`, `template`, `http_split`, `sensitive_file`, `cms_probing`, `recon`, `proto_pollution`, `code_injection`.

ReDoS protection: `validate_pattern_safety` rejects patterns whose probes exceed 50ms or hit known dangerous constructs. Built-in (compile-time-vetted) patterns match directly with no per-match timeout; only custom patterns added via `add_pattern(..., custom=True)` run through the shared thread-pool safe-matcher with a timeout. Four consecutive timeouts recycle the pool.

See [the detection reference](references/detection.md) for the detect return shape, `DetectionResult`, semantic scoring, and tuning knobs.

## Telemetry

Two tiers. Raw is free and standards-based; enriched is guard-agent-gated.

| Tier | Gate | What exporters see |
|---|---|---|
| Raw | `enable_otel=True` and/or `enable_logfire=True` | All event types, all metrics, W3C traceparent continuation, muting. No `guard.*` enrichment. |
| Enriched | `enable_agent=True` + `enable_enrichment=True` | Raw plus `guard.project_id`, `guard.service.name`, `guard.deployment.environment`, `guard.threat_score`, `guard.rule.id`/`version`, `guard.behavior.correlation_key`/`recent_event_count`. |

`enable_enrichment=True` without `enable_agent=True` raises `ValidationError`.

Mute via `muted_event_types`, `muted_metric_types`, `muted_check_logs` (validated sets; unknown values raise `ValidationError` listing valid values). Valid values: `EVENT_TYPE_VALUES` (33), `METRIC_TYPE_VALUES` (3: `error_rate`, `request_count`, `response_time`), `CHECK_NAME_VALUES` (17, matching the pipeline order above).

See [the telemetry reference](references/telemetry.md) for the full config surface, enrichment field sources, and exporter wiring.

## Footguns

* **Logfire + Pydantic instrumentation is muted once telemetry is actually enabled, not at import.** A host app calling `logfire.instrument_pydantic()` would otherwise emit one span per `SecurityEvent`/`SecurityMetric` validation and one per `EventBatch` re-validation on every flush (hundreds of thousands of spans/day under real traffic). `guard_core._pydantic_plugin_mute.get_telemetry_model()` is the supported way to reach a guard-agent telemetry model class: it mutes first and returns the class second. Three repository checks back that up, and only the third proves the property that matters. An AST scan rejects the known shapes — a plain import, an aliased import, a submodule import followed by attribute access, and the `importlib.import_module`/`__import__` indirection builtins — from any module outside a two-file allowlist (`_pydantic_plugin_mute.py` itself, and `models.py` for `AgentConfig` alone, which is not a telemetry model), but only at edit time, only for a literal module name, and only over source that exists on disk. A `sys.meta_path` finder installed for the whole test session records the caller of every `guard_agent` import the interpreter actually resolves and fails the session if one outside that same allowlist ever ran — but `sys.meta_path` is consulted only on a `sys.modules` cache miss, and the allowlisted mute module is normally the first thing in a session to import `guard_agent` legitimately, so in practice the finder only ever gets a chance to catch the *first* importer; every import after that, dynamic or not, is served from the cache and invisible to it, 100% coverage notwithstanding. What actually holds is a `pytest_sessionfinish` assertion in `tests/conftest.py`: if `guard_agent` is in `sys.modules` at session end, `SecurityEvent`/`SecurityMetric`/`EventBatch` must each carry `plugin_settings == {"logfire": {"record": "off"}}`, read straight out of `sys.modules` so the check cannot cause the import it is testing for. That property does not care how the import happened, only whether it ended up muted; with the suite at 100% coverage that is a real claim about this run, not a universal guarantee. `SecurityConfig.to_agent_config()` (the `enable_agent=True` path) and `HandlerInitializer.initialize_agent_integrations()` (the `enable_otel`/`enable_logfire`/`enable_enrichment` path, which can wire a telemetry-capable handler with no agent at all) both call the underlying idempotent mute directly too, since they are the points a configuration first needs `guard_agent` at all: the mute lands there rather than at `import guard_core`, and a configuration with all of `enable_agent`/`enable_otel`/`enable_logfire`/`enable_enrichment` off never pays the `guard-agent`/`cryptography` import cost. **Caveat:** a host application that constructs `SecurityEvent`/`SecurityMetric`/`EventBatch` through its own path outside guard-core is not covered by any of guard-core's three checks, but it is not left unmuted either: guard-agent 2.8.0 and later apply the identical mute from their own `__init__`, so importing `guard_agent` at all covers that path. Only a host pinning guard-agent below 2.8.0 and building those models outside guard-core has to mute them itself. See [the telemetry reference](references/telemetry.md) for the postmortem detail.
* **`fail_secure=True` by default.** A buggy check surfaces as 500s, not silent bypasses. Keep the default and fix the check; do not flip to fail-open without reason.
* **Redis defaults to on.** `enable_redis=True` with `redis://localhost:6379`. Set `enable_redis=False` if there is no Redis, or every stateful check will try to connect.
* **`enable_enrichment=True` requires `enable_agent=True`.** Mismatch raises `ValidationError` at config time.
* **`guard_agent` is optional.** `import guard_agent` failures are swallowed; the mute function and the agent handler no-op gracefully. Do not assume guard-agent is present.

## Sync mirror

`guard_core.sync.*` is generated from `guard_core.*` via unasync (`make sync` in the repo). Never hand-edit files under `guard_core/sync/`; edit the async source and regenerate. If you are reading behavior, read the async tree and trust the sync mirror to match.

## Tooling

The repo uses uv, Ruff, mypy, pytest (with `pytest-asyncio`, `asyncio_mode="auto"`), and a 100% coverage gate (`make local-test`). Run the full suite before claiming green; subset runs have shipped cross-file contract bugs. Integration tests are marked `integration` and skipped by default.
