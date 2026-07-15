# Modular Architecture (GuardEngine + Providers + Modules) — Design

- **Date**: 2026-07-11
- **Status**: Approved by maintainer (conversation, 2026-07-11)
- **Scope**: guard-core internal architecture + `SecurityConfig` shape; adapter contract changes limited to pipeline assembly and engine delegation
- **Not tracked in git** (planning artifact, per repo policy)

## 1. Motivation

Contributing a feature to guard-core today touches ~10 places: a check in
`core/checks/implementations/`, registration copy-pasted into **every
adapter** (fastapi-guard `guard/middleware.py:267-283` hand-lists all 17
checks; flaskapi/djapi carry their own copies), fields in the 92-field flat
`SecurityConfig` plus validators, handler wiring in `HandlerInitializer`,
event types, `to_agent_config()`, the generated sync mirror, docs in four
files, and the 100%-coverage/xenon/vulture gate. Checks receive the whole
middleware object (`SomeCheck(self)`), so writing one requires understanding
all of it. Import-time singletons caused a shipped bug (v3.4.0: every
`detection_*` setting silently inert in production because
`sus_patterns_handler` was constructed at import with no config).

Goals, in priority order:

1. **Contribution locality** — a feature is one directory plus one registry
   line. Narrow, declared dependencies instead of the middleware god object.
2. **Plug-and-play with secure defaults** — absent module = zero code in the
   request path; `SecurityConfig()` with no arguments still assembles the
   full default pipeline.
3. **Kill the singleton bug class** — config-at-import-time can never recur;
   engine-owned instances only.
4. **Config-time composition for performance** — enablement decided at build,
   never via per-request `if enabled` branching; pattern sets compiled once
   per config.
5. Long-term: community-contributable modules (CRS/CrowdSec-style ecosystem
   lever). Explicitly **not** a v1 commitment (see Decisions).

## 2. Decisions (settled with maintainer)

| Decision | Choice |
| --- | --- |
| Default behavior | `SecurityConfig()` = full default pipeline, secure-by-default. Disabling = removing/`None`-ing a module group, never a runtime flag inside a check. |
| Migration | Strangler across 3.x releases, each phase shippable and behavior-identical. No big-bang v4. |
| Rust core | Python-first, portable by discipline: module configs stay plain data; the 6 callable/object fields are isolated in an explicit extension-points bucket. No cross-language protocol work now. |
| Extension API audience | Internal-first, public-shaped. No stability promise until the protocol survives the migration; entry-point auto-discovery rejected (supply-chain footgun for a security library). Third-party/custom checks keep working via existing hooks meanwhile. |
| Check ordering | Engine-owned. `DEFAULT_MODULES` registry order is the pipeline order. No user-shuffleable ordering, no priority system in v1. |
| Approach | A-via-B: destination is engine+providers+module registry; first milestones are the registry-free decouplings (pipeline factory, contexts, singleton removal), each independently shippable. |
| `custom_log_file` / `log_format` | Intentional features (custom log filename; custom output format). CORRECTION (2026-07-11 plan investigation): they ARE wired — at the adapter layer (fastapi-guard `guard/middleware.py:50-51` passes both into `setup_custom_logging`). No guard-core consumer because logging setup is an adapter entry-point concern. **No Phase 0 action.** |

## 3. Current-state findings (investigation, 2026-07-10/11)

Consumer-verified by three exploration passes; file:line references are to
current `master` (v3.4.0, commit a06201a era).

### 3.1 Check coupling

- All 17 checks constructed with the whole middleware; `base.py:13-15` copies
  `middleware.config`/`.logger`. The base class's narrowing wrappers
  (`send_event`, `create_error_response`, `is_passive_mode`,
  `log_if_allowed`) are used by **zero** concrete checks — every check
  reaches `self.middleware.*` directly.
- Shared-need ranking across checks: `config` (17), `logger` (17),
  `event_bus` (14), `create_error_response` (11, +2 use raw
  `response_factory`), `route_resolver` (5), `agent_handler` (2), everything
  else single-check.
- `request.state` contract: `route_config` (produced by RouteConfigCheck,
  consumed by 12 checks), `client_ip` (5 consumers), `is_whitelisted`
  (produced only in ip_security's **global** branch, softly consumed by 4),
  `_guard_pipeline_start` (event-bus timing).
- Pipeline (`core/checks/pipeline.py:22-24`) awaits every check on every
  request; disabled features early-return inside checks. Fail-secure path
  reads `check.config.fail_secure` (`pipeline.py:49`).
- 10/17 checks fit cleanly in {config slice, event bus, error responses} +
  ambient state. Hard cases: `suspicious_activity` (raw
  `middleware.suspicious_request_counts` dict mutated in place; reaches
  `sus_patterns_handler` two frames down inside `utils.py` without importing
  it), `ip_security` (route_resolver + geo + `ip_ban_manager` singleton),
  `rate_limit` (geo via `config.geo_ip_handler` while ip_security uses
  `middleware.geo_ip_handler` — two access paths for one concept),
  `cloud_ip_refresh` (its "handler" is a bare timestamp + method on the
  middleware), `route_config` (depends on adapter pre-setting
  `state.guard_decorator`/`guard_route_id`).
- `helpers.py` is already parameter-passing style except
  `check_route_ip_access(..., middleware)` which reaches in solely for
  `geo_ip_handler` (`helpers.py:79`) — one-line fix.

### 3.2 Handlers, singletons, initialization

- Import-time singletons (constructed by importing `guard_core`):
  `ip_ban_manager` (`ipban_handler.py:239`), `cloud_handler`
  (`cloud_handler.py:492`), `security_headers_manager`
  (`security_headers_handler.py:457`), `sus_patterns_handler`
  (`suspatterns_handler.py:1077`).
- `__new__` singletons with inconsistent config semantics: `RedisManager` and
  `RateLimitManager` overwrite the shared instance's config on every
  construction; `DynamicRuleManager` keeps only the **first** config forever
  (`dynamic_rule_handler.py:47`); `IPInfoManager` requires a token and can be
  constructed **inside Pydantic validation** as a side effect
  (`models.py:663-680`).
- `CorsHandler` (`cors_handler.py:26-27`) is the target shape already: plain
  `__init__`, per-middleware instance, no initializer involvement.
- `BehaviorTracker` split-brain: `handler_initializer.py:51-53` and
  `decorators/base.py:60` can construct two independent instances; only the
  decorator-owned one gets Redis/agent wiring.
- Provider seams today: `RedisHandlerProtocol` (clean, adapter-injected only,
  raw `get_connection()` escape hatch needed for rate-limit Lua);
  `GeoIPHandler` protocol (exists); telemetry is already a de-facto provider
  (`CompositeAgentHandler` fanning out to duck-typed agent/OTel/Logfire
  exporters); HTTP has **no seam** — 8 ad-hoc `aiohttp.ClientSession()`
  sites (7 in `cloud_handler.py`, 1 in `ipinfo_handler.py:127`).
- Redis namespaces: 4 access shapes (TTL KV; `KEYS` scans in behavior; raw
  ZSET+Lua in ratelimit bypassing `get_key`; whole-mmdb blob in ipinfo).
  Known warts: `banned_networks:*` never cleared by `reset()`; dead
  `cloud_ranges_v2` path; `security_headers_manager.initialize_redis()` is
  never called anywhere (orphaned capability).
- Init order constraints: sync middleware `__init__` (rate-limit manager,
  header configure, Redis, agent, event bus, initializer, resolver, contexts,
  CORS) → async `initialize()` (pipeline build → decorator handoff →
  `initialize_redis_handlers()` → `initialize_agent_integrations()` with
  redis-before-agent cross-wiring → middleware swaps in composite handlers).
  fastapi-guard's `_middleware_state` warm-cache keyed by `id(config)`
  short-circuits re-init.
- unasync (`scripts/unasync.py`): protocols with plain `async def` stubs are
  mechanically mirrored (like `cloud_ip_store_protocol.py`); anything richer
  joins the 6 hand-maintained `TEMPLATE_FILES` twins forever. New provider
  protocols MUST use plain async-def stubs.

### 3.3 Config census (92 fields → groups)

Consumer-verified grouping: core 10 (`passive_mode`, `fail_secure`,
`muted_check_logs`, `log_suspicious_level`, `log_request_level`,
`log_format`, `custom_log_file`, `exclude_paths`, `trusted_proxies`,
`trusted_proxy_depth`); rate_limit 4; detection 16 (all tuning knobs funnel
through `SusPatternsManager._apply_enhanced_config`,
`suspatterns_handler.py:463-481`; engine internals never read config
directly); ip_access 6; geo 6 (incl. 2 deprecated ipinfo fields); cloud 3;
user_agent 1; https 2; behavioral 1; cors 7 (NOT a pipeline check — adapter
calls `CorsHandler` directly); security_headers 1; hooks 4; agent 14 (12
route exclusively through `to_agent_config()`); dynamic_rules 2; emergency 2;
redis 3; muted 2; otel 4; logfire 2; enrichment 1; lazy_init 1.

- True cross-cutting (3+ features): `passive_mode`, `muted_check_logs`,
  `log_suspicious_level`, `trusted_proxies`(+depth), `exclude_paths`,
  `enable_redis`/`redis_prefix`, plus dynamic-rules write targets.
- Validators: 10 field-validators + 3 model-validators. 11 are single-module
  syntax/membership checks (move onto module sub-configs). 2 encode
  cross-module deps and move to engine assembly:
  `validate_geo_ip_handler_exists` (auto-construction side effect) and
  `validate_agent_config` (`enable_dynamic_rules`/`enable_enrichment` →
  `enable_agent`). The `muted_*` validators need a registry-supplied
  enumeration (module-declared event types / check names) instead of
  hardcoded sets.
- `to_agent_config()` (`models.py:772-799`): exact 13-field wire contract to
  the separately-versioned `guard_agent` package — preserved byte-for-byte.
- Route overrides are FOUR patterns today: (1) per-field null-coalesce
  (detection exclusions — the good one), (2) additive merge (user-agent
  lists, behavior rules), (3) seed-then-override at construction
  (`enable_penetration_detection` → `RouteConfig.enable_suspicious_detection`,
  `decorators/base.py:73-75`), (4) **presence-switch bug**: any route with a
  `RouteConfig` object skips global IP/country checks entirely
  (`ip_security.py:142-147` + `helpers.py:63-86` returning pass when route
  sets no IP fields). Plus a layered waterfall for rate limits.
- Route-only features with no global config (correct as-is): auth,
  required_headers/api_key, referrer, time_window, size/content.
- Portability: 6 callable/object fields (`geo_ip_handler`, `cloud_ip_store`,
  `custom_request_check`, `custom_response_modifier`, `on_error`, route-level
  `custom_validators`) — the extension-points bucket a Rust core would keep
  Python-side. Remaining ~75 fields are plain data.
- Dynamic rules: `_SNAPSHOT_FIELDS` (`dynamic_rule_handler.py:26-40`)
  hardcodes 13 field names across 7 features and `setattr`s them on the live
  shared config with snapshot/rollback (`:198-228`).

### 3.4 Defects found (feed Phase 0)

1. **Security bug**: RouteConfig presence disables global IP
   whitelist/blacklist + country rules on that route (pattern 4 above).
2. `geo_ip_db_max_age` validated/documented/tested but never passed to
   `IPInfoManager` (`models.py:671-673` omits `max_age=`) — zero runtime
   effect.
3. RETRACTED — `custom_log_file`/`log_format` are wired at the adapter
   layer (fastapi-guard `guard/middleware.py:50-51`); the "never wired"
   finding only held for guard-core itself, where no wiring is expected.
   No action.
4. Banned-IP block path emits no event (`ip_security.py:19-45`) — repeat
   requests from banned IPs are telemetry-invisible.
5. Duplicated event-string literals instead of constants
   (`custom_request.py:18`, `emergency_mode.py:35`,
   `request_size_content.py:37,79`, `user_agent.py:47`); orphan event type
   `"dynamic_rule_violation"` (`rate_limit.py:69`) missing from
   `EVENT_TYPE_VALUES`.
6. Dead `RouteConfig.session_limits` (`decorators/base.py:39`) — never set,
   never read.
7. Per-regex-match `ThreadPoolExecutor(max_workers=1)`
   (`detection_engine/compiler.py:106-128`) — dominant engine overhead.
8. `is_whitelisted` only populated in the global branch, so downstream
   whitelist short-circuits no-op on decorated routes (subsumed by fix #1's
   semantics unification).

## 4. Target architecture

### 4.1 GuardEngine

`GuardEngine` owns providers, module runtimes, handlers, event bus, response
factory, route resolver, dynamic-rules service, and the pipeline. Adapters
construct one engine per app from `SecurityConfig` and delegate
(`engine.process(request)` semantics; adapter keeps request/response
wrapping, CORS interception, and framework glue). Absorbs
`HandlerInitializer`; replaces all singleton state. fastapi-guard's
`_middleware_state` id(config) registry becomes unnecessary once the adapter
holds exactly one engine (lifespan + request path share it by construction).

Assembly (`build_engine(config) -> GuardEngine`):

1. Normalize config (flat→group shim).
2. Determine active modules (group present → module active).
3. Validate provider requirements → actionable errors
   ("CountryModule requires a geo provider; pass `geo=` or set
   `geo_ip_handler`").
4. Build providers → module handlers → checks → pipeline
   (preamble + ordered active checks).

Startup order preserved from today: cache → telemetry (agent cross-wiring
after cache) → geo/cloud (optionally deferred via `lazy_init`) → dynamic
rules service.

### 4.2 Providers

| Provider | Interface | Notes |
| --- | --- | --- |
| cache | existing `RedisHandlerProtocol` + `get_connection()` raw escape hatch | Modules keep their own in-memory fallbacks (semantics legitimately differ). All key prefixes route through provider; no reaching into `redis_handler.config.redis_prefix`. |
| geo | existing `GeoIPHandler` protocol | `IPInfoManager` de-singletoned; construction moves from Pydantic validator to engine assembly; `max_age` wired. `geo_ip_handler` config field remains the injection point (compatibility). |
| telemetry | new `TelemetryExporter` protocol formalizing the duck-typed shape `CompositeAgentHandler` already fans out to | Agent/OTel/Logfire become formal exporters; muting = event filter config. Mostly typing, not new machinery. |
| http | new, minimal (`get(url, timeout) -> bytes`) | One shared session + retry/timeout policy; replaces 8 ad-hoc `aiohttp.ClientSession()` sites. |

All provider protocol methods are plain `async def` stubs → sync mirror stays
mechanically generated.

### 4.3 Core services (engine-owned, not modules)

Event bus, error-response factory, route-config resolver, client-identity
(IP extraction with trusted proxies), dynamic-rules service, pipeline.
CORS stays a core handler invoked by adapters (it is not a pipeline check
today and stays that way).

### 4.4 Module protocol

```python
@dataclass(frozen=True)
class ModuleSpec:
    name: str
    config_model: type[BaseModel] | None
    requires: frozenset[str] = frozenset()        # provider names
    check_factories: tuple[CheckFactory, ...] = ()
    handler_factory: HandlerFactory | None = None
    event_types: frozenset[str] = frozenset()      # feeds muting-validator registry
    dynamic_fields: frozenset[str] = frozenset()   # DynamicRulesService write scope
```

Directory layout (one feature = one directory + one registry line):

```
guard_core/modules/rate_limit/
    __init__.py   # exports SPEC
    config.py     # RateLimitConfig
    check.py      # RateLimitCheck
    handler.py    # RateLimitManager (de-singletoned)
    events.py
```

`guard_core/modules/registry.py` holds `DEFAULT_MODULES: tuple[ModuleSpec, ...]`
in canonical pipeline order (engine-owned). v1 has no ordering metadata and
no third-party insertion API (deferred until public). Module set:
rate_limit, detection (suspicious_activity + patterns engine), ip_access
(ban + allow/deny), geo_country (requires geo provider; separate from
ip_access precisely because their provider deps differ), cloud (blocking +
refresh), user_agent, https, referrer, auth_headers (authentication +
required_headers), time_window, size_content, behavioral, emergency,
custom_hooks (custom_request + custom_validators), request_logging,
security_headers (handler-only, no check). Telemetry settings
(agent/otel/logfire/muting) are provider-layer config consumed at engine
assembly, not a module. Exact final grouping may merge/split during ports;
registry order preserves today's documented check order.

### 4.5 CheckContext and pipeline preamble

```python
@dataclass
class CheckContext:
    core: CoreConfig                 # passive_mode, fail_secure, muted_check_logs, log levels
    logger: logging.Logger
    events: SecurityEventBus
    responses: ErrorResponseFactory
    routes: RouteConfigResolver
    providers: ProviderRegistry      # .cache/.geo/.telemetry/.http, None when absent
```

- Checks constructed by their module: `Check(ctx, module_config, handler)`.
- Pipeline fail-secure path reads `ctx.core.fail_secure`.
- **Preamble**: route-config resolution + client-IP extraction leave the
  check list and run as engine preamble (never block, only populate state).
  Removes the 12-check ordering dependency by construction; deletes
  emergency_mode's defensive re-extraction.
- `request.state` keys documented as the formal contract: `route_config`,
  `client_ip`, `is_whitelisted` (populated correctly on ALL branches after
  the Phase 0 fix), `_guard_pipeline_start`.
- `suspicious_request_counts` raw dict becomes module-owned state inside the
  detection module's handler.

### 4.6 Config shape

```python
SecurityConfig(
    passive_mode=False,                       # core fields stay top-level
    rate_limiting=RateLimitConfig(limit=10, window=60),
    detection=DetectionConfig(categories={...}),
    ip_access=IpAccessConfig(whitelist=[...]),
    telemetry=TelemetryConfig(agent=AgentExport(...), otel=OtelExport(...)),
)
```

- **Enablement rule (uniform)**: group present = module on; group `None` =
  module off; `SecurityConfig()` instantiates every default-on group →
  today's full pipeline. Replaces 16 `enable_*` flags +
  presence-means-enabled lists + the RouteConfig presence switch.
  Default-on/off per group preserves today's defaults exactly.
- **Flat compatibility shim**: `mode="before"` model validator routes known
  flat kwargs into groups. Explicit group wins; flat+group conflict =
  validation error. Deprecation warnings deferred; removal 4.0 at earliest.
- **Collisions**: `security_headers` dict coerces into
  `SecurityHeadersConfig` via Pydantic; `rate_limiting` group name coexists
  with legacy `rate_limit` int. Others don't collide.
- `to_agent_config()` output unchanged (13-field contract).
- Extension-points bucket: the 6 callable/object fields stay as config fields
  (compatibility) but are grouped/documented as the non-portable subset.
- Cross-module validators move to engine assembly with actionable messages;
  single-module validators move onto their sub-configs; muting validators
  consume the module-declared registry.
- Route-only features keep having no global group.

### 4.7 Route-override semantics

Unify on per-field null-coalescence (route value if set, else global).
Documented additive exceptions: user-agent blocklists, behavior rules.
Fixes defect #1 (global IP/country rules always consulted unless the route
explicitly overrides those fields). Naming mismatches
(`enforce_https`/`require_https`, `blacklist`/`ip_blacklist`,
`enable_penetration_detection`/`enable_suspicious_detection`) are kept and
documented; renames deferred to the public-API pass. `RouteConfig` stays one
shared class in v1 (module-contributed route fields deferred).

### 4.8 DynamicRulesService

Privileged core service (not a module). Modules declare `dynamic_fields`;
the service applies rule sets transactionally against module runtime configs
(same snapshot/rollback semantics as today, no raw `setattr` across
ownership lines). Emergency mode stays core-owned and service-writable.
"Dynamic rules require agent" becomes an engine-build error. (Live-reload
for self-hosted users without the agent is a separate future feature this
API deliberately enables — out of scope here.)

### 4.9 Performance items in scope

- Absent module → zero request-path cost (composition, automatic).
- Detection compiles only enabled categories' patterns once at module build.
- Shared executor replaces per-match `ThreadPoolExecutor`; compile-time-vetted
  patterns skip the timeout wrapper entirely (Phase 0, independent).

Out of scope here (fastapi-guard work, tracked separately): pure-ASGI
rewrite, per-request route-resolution cache, WebSocket coverage.

## 5. Migration phases (each ships as a normal 3.x release, behavior-identical unless stated)

- **Phase 0 — standalone fixes, land immediately** (behavior changes are
  bug fixes, changelogged): defects of §3.4 except the retracted #3, incl.
  the shared-executor detection fix.
- **Phase 1 — pipeline factory**: `build_default_pipeline()` in guard-core;
  adapters delete copy-pasted check lists. Makes "adapters automatically
  pick up new checks" true.
- **Phase 2 — CheckContext + preamble**: `SecurityCheck.__init__(ctx, ...)`;
  route_config/client_ip extraction becomes preamble; `helpers.py` fully
  de-middleware'd; pipeline reads `ctx.core.fail_secure`.
- **Phase 3 — providers + singleton removal**: protocols formalized
  (cache/geo/telemetry/http); import-time and `__new__` singletons replaced
  by engine-owned instances one at a time; `HandlerInitializer` absorbed
  into engine assembly; `BehaviorTracker` split-brain resolved;
  `_middleware_state` reduced/removed in the adapter.
- **Phase 4 — ModuleSpec + registry + reference ports**: `user_agent` first
  (trivial: config group + check), then `rate_limit` (provider dep, handler
  lifecycle, Lua escape hatch, route overrides). CONTRIBUTING.md rewritten
  around the worked example.
- **Phase 5 — port the rest**: remaining modules (detection last),
  DynamicRulesService conversion, complete config groups + flat shim,
  per-module docs; stale docs (`api-surface-audit.md` field count,
  category counts, undocumented detection knobs) regenerated per module.
- **Phase 6 — deferred (4.0-era)**: flat-field deprecation/removal, public
  extension API decision, RouteConfig decomposition, route-override renames.

Every phase exits green on the full quality suite (ruff, mypy strict,
xenon/radon, bandit, vulture, deptry), 100% line+branch coverage, sync
mirror regenerated (`make check-sync`), and the attack-simulation baseline
(`detection_rate >= 0.8568`, `fp_rate <= 0.0` +0.02 tolerance) unchanged.

## 6. Testing strategy

- **Behavior lock**: full existing suite (1,815 tests) + attack-simulation
  corpus baseline as the detection-regression gate on every phase.
- **New surface**: engine-assembly tests (module selection from config,
  provider-requirement errors, startup ordering); per-module isolation tests
  (module + fake providers, no middleware) — this pattern IS the
  contributor-facing example; provider contract tests (memory vs redis
  implementations against the same protocol assertions).
- **Adapter contract test** (in fastapi-guard): pins that detection/module
  config reaches the engine at startup — closes the v3.4.0-class silent
  regression permanently.
- **unasync**: new protocols as plain async-def stubs; `make check-sync` in
  CI covers the mirror.

## 7. Out of scope

fastapi-guard pure-ASGI rewrite, WebSocket protection, route-resolution
cache, OpenAPI security-scheme registration, CrowdSec/prompt-injection
modules (future modules once the system exists), live-reload for
self-hosted, Rust core work, distribution/marketing items.

## 8. Risks

| Risk | Mitigation |
| --- | --- |
| Behavior drift during ports | Phase gates: full suite + attack-sim baseline per phase; ports are mechanical moves, not rewrites. |
| Adapter/version coupling breaks mid-migration (has happened: fastapi-guard 7.1.1) | Additive-only guard-core API during 3.x; adapters migrate per phase behind unchanged public exports; adapter contract test. |
| Sync-mirror divergence | Plain async-def protocol stubs; `make check-sync` gate. |
| Config shim ambiguity (flat vs group) | Explicit precedence rule + conflict = validation error; exhaustive shim tests per field. |
| Dynamic-rules scope creep | Service API limited to module-declared `dynamic_fields`; existing snapshot/rollback semantics preserved verbatim. |
