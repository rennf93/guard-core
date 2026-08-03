---

title: Release Notes - Guard Core
description: Release notes for Guard Core, detailing new features, improvements, and bug fixes
keywords: release notes, guard-core, security library, api security
---

Release Notes
=============

___

v3.8.1 (2026-08-03)
-------------------

Stop the inert-lazy_init warning, complete the preempted-header warning's advice, and make global whitelist_countries actually restrict (v3.8.1)
------------------------------------------------------------------------------------------------------------------------------------------------

### Fixed

- `HandlerInitializer`'s "lazy_init has no effect without Redis" warning, introduced in v3.8.0, fired whenever Redis was disabled and a cloud-IP or geo-IP path existed — regardless of whether `lazy_init` was actually enabled. Because `SecurityConfig.lazy_init` defaults to `True`, a user who never opted into lazy init and never uses Redis still saw the warning on every startup. The check now returns early unless `lazy_init` is actually `True`, so it only warns the user who genuinely asked for lazy init and won't get it.
- The preempted-forwarded-header warning introduced in v3.7.1 told users to disable the app server's forwarded-header handling (`uvicorn --no-proxy-headers`, `proxy_headers=False`) and declare `trusted_proxies`, but omitted `trust_x_forwarded_proto`. A user who followed the first step alone — the obvious reading — broke HTTPS detection on a TLS-terminating host (Render, Heroku, a CDN): with `proxy_headers` off the server stops forwarding the URL scheme, and `https_enforcement` only honours `X-Forwarded-Proto` when `trusted_proxies` is populated and `trust_x_forwarded_proto=True`, so under `enforce_https=True` it saw plain HTTP and redirect-looped. The warning now names all three settings and calls out the redirect-loop risk.
- `whitelist_countries` at the global `SecurityConfig` level was exemption-only: a country in neither `whitelist_countries` nor `blocked_countries` was allowed, and with no `blocked_countries` set it was a complete no-op. This contradicted the field's documented meaning, the route-level `allow_countries` decorator (which already restricted), and the sibling IP `whitelist` field (which already restricted). The global country check now treats a non-empty `whitelist_countries` as a true allow-list: only listed countries pass, an unresolved country is blocked (fail-closed, matching `allow_countries`), and an explicit match overrides `blocked_countries`.

### Behaviour changes

- The inert-lazy_init warning now fires only when `lazy_init=True`; with the default or `lazy_init=False` it is silent.
- Only the preempted-forwarded-header warning's message text changed; `extract_client_ip` returns the same value in every case and the warning still fires at most once per process.
- A non-empty `whitelist_countries` now restricts traffic to the listed countries. Previously it only exempted listed countries from `blocked_countries` and otherwise allowed everything, so a user who set `whitelist_countries=["US","CA"]` expecting "only US/CA" got default-allow. Non-listed countries are now blocked; users who combined `whitelist_countries` with `blocked_countries` expecting exemption-only semantics will see non-listed countries blocked too. This aligns the field with its name and docs.

___

v3.8.0 (2026-07-31)
-------------------

Stop the anomaly telemetry burst and two recon false positives (v3.8.0)
-------------------------------------------------------------------------

### Added

- `CloudManager.is_cloud_ip()` now logs a rate-limited `WARNING` (at most once every 300 seconds per provider) the first time it evaluates a provider whose IP ranges are not yet populated — previously this failed open in total silence, with no signal that the check was a no-op. The return value is unchanged in every case.
- `cloud_handler.get_status()` and the `IPInfoManager` instance's `get_status()` report per-subsystem `ready` / `last_refreshed` / `entries`; `IPInfoManager` gains `last_refreshed` and `entry_count` (`reader.metadata().node_count`) for parity with `CloudManager`'s existing `last_updated` / `ip_ranges` introspection. Adapters expose both combined via their status surface (fastapi-guard: `SecurityMiddleware.get_initialization_status()` / `GET /_guard/status`), cheap enough to back a Kubernetes/ALB warmup probe or health endpoint. See [Provider Status](configuration/security-config.md#provider-status).
- `HandlerInitializer` now warns when `lazy_init` is configured but has no effect (Redis disabled, so its only consulted branch is unreachable) and when `SecurityConfig.geo_ip_handler` is set without `blocked_countries` / `whitelist_countries` (constructed but never initialized). Both are warnings only; neither raises or changes behaviour.
- `IPInfoManager.get_country()`'s uninitialized-reader warning now distinguishes a startup race (never yet attempted) from a permanently failed initialization (already attempted and failed), so the log line reads differently for "still warming up" versus "check the token and network."

### Fixed

- `PerformanceMonitor._detect_statistical_anomaly` compared `abs(z_score)` against `anomaly_threshold`, so a pattern running faster than its own rolling average tripped `statistical_anomaly` exactly as often as one running slower. A regex finishing early is not an anomaly; only `z_score > anomaly_threshold` (slower than average) is checked now.
- Anomaly-event emission had no rate limiting: `_check_anomalies` sent a `pattern_anomaly_*` event to the agent handler for every tripping metric, so a single host-wide stall (GC pause, cron job, backup, noisy-neighbour CPU contention) that inflated every tracked pattern's execution time at once produced one event per pattern, all sharing a timestamp. A production customer reported thousands of `pattern_anomaly_statistical_anomaly` events from a single incident, which also consumed their metered event quota. `PerformanceMonitor` now takes a new `anomaly_emission_cooldown` constructor parameter (default `60.0` seconds, clamped `1.0`-`3600.0`) tracked per pattern on `PatternStats`; once a pattern emits an anomaly event it will not emit another until the cooldown elapses, while a pattern that is genuinely and continuously slow still reports, just at most once per window. The cooldown state lives inside the same `PatternStats` entry that `max_tracked_patterns` already evicts, so it cannot accumulate unbounded memory. Callbacks registered via `register_anomaly_callback` are unaffected by the cooldown and still run on every trip — they execute in-process at no quota cost, and applications may depend on per-execution granularity (for example, a local circuit breaker).
- The builtin `recon` regex flagged requests for `robots.txt`, `sitemap.xml`, and `security.txt` as reconnaissance. All three are standards-defined files meant to be fetched publicly — `robots.txt` is RFC 9309, `sitemap.xml` is the sitemaps.org protocol and is deliberately submitted to search engines, `security.txt` is RFC 9116 and exists specifically so security researchers can find it — and every crawler, browser, link-preview fetcher, and mobile app requests them as routine behaviour. A production customer had their own phone flagged as a high-severity threat for fetching `/robots.txt` from their own site. The three entries are removed from the alternation; `readme.txt`, `README.md`, `CHANGELOG`, `pom.xml`, `build.gradle`, `appsettings.json`, and `crossdomain.xml` remain, since those are genuine information-disclosure signals rather than standards-defined public files.

### Behaviour changes

- Requests for `/robots.txt`, `/sitemap.xml`, and `/security.txt` no longer match the `recon` category; the other entries in that pattern are unaffected. Only slower-than-average pattern executions can trip `statistical_anomaly` — faster ones, previously flagged too, no longer are. `pattern_anomaly_*` events sent to the agent handler are now rate-limited to at most one per pattern per `anomaly_emission_cooldown` window (default 60s); this does not change `anomaly_callbacks` behaviour, `timeout`/`slow_execution` detection, or the `get_problematic_patterns`/`get_slow_patterns` diagnostics.
- None from the observability additions above: `is_cloud_ip()` and `check_ip_country()` return exactly what they returned before in every case (locked in by new regression tests); the new warnings and `get_status()` / `get_initialization_status()` accessors are additive and read-only.

___

v3.7.1 (2026-07-30)
-------------------

Detect when the app server has already resolved the client from X-Forwarded-For (v3.7.1)
-----------------------------------------------------------------------------------------

### Added

- A one-time warning when the connecting IP appears inside its own `X-Forwarded-For` chain. ASGI/WSGI servers apply forwarded headers before any middleware runs — uvicorn defaults to `proxy_headers=True` with `forwarded_allow_ips="127.0.0.1"`, and a same-host reverse proxy always connects from loopback — so `request.client_host`, which `extract_client_ip` uses for the entire `trusted_proxies` decision, may already have been rewritten from the header. A genuine proxy appends the address it received the connection from and never lists its own, so the connecting IP turning up among the header's entries means something upstream resolved it first. Two consequences this surfaces: with `trusted_proxies` unset — documented as "no declared proxy, so `X-Forwarded-For` is never trusted" — the returned address is whatever the client claimed, so a rotating header defeats rate limiting and IP banning entirely; and once the server has pre-resolved the peer it no longer matches a declared proxy, so legitimate traffic trips the spoofing branch and emits `spoofing_detected` on every request. Verified end to end with `trusted_proxies` unset at `rate_limit=3/60s`, one caller rotating `X-Forwarded-For`: 12 of 12 requests were served under uvicorn's default, versus 3 served and 9 rate-limited with `--no-proxy-headers`. The remediation is to disable the server's own handling (`uvicorn --no-proxy-headers`, or `proxy_headers=False` in `uvicorn.run`; gunicorn, hypercorn and WSGI servers have equivalent settings) and declare the proxy through `trusted_proxies` / `trusted_proxy_depth` so guard-core is the single authority. Same bug class as [GHSA-77q8-qmj7-x7pp](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-77q8-qmj7-x7pp) / CVE-2025-46814, one layer further out.
- Deployment guidance in `docs/internals/ip-management.md` and a cross-reference in `docs/configuration/security-config.md`. Neither guard-core nor its adapters previously mentioned the app server's forwarded-header handling anywhere.

### Behaviour changes

- None. This release is observability only: `extract_client_ip` returns exactly what it returned before in every case, the existing spoof warning and `spoofing_detected` event are unchanged, and the new warning is emitted at most once per process. The true socket peer cannot be recovered once the server has overwritten it, so guard-core reports the condition rather than pretending to repair it.

___

v3.7.0 (2026-07-29)
-------------------

Opt-in enforcement when an adapter cannot resolve the route (v3.7.0)
--------------------------------------------------------------------

### Added

- `SecurityConfig.route_resolution_strict` (default `False`). A missing `RouteConfig` has always meant two different things — the route carries no decorators, or the adapter failed to match the request to its route — and every per-route check treats both as "nothing to enforce". The first is correct and unchanged; the second silently disables the checks the route does declare, which is how [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378) turned a route-matching bug in the Starlette adapter into an unauthenticated bypass of `@require_auth`. Adapters now report a failed match by setting `request.state.guard_route_unresolved = True`, and with `route_resolution_strict=True` those requests are logged, emit the new `route_unresolved` event, and are blocked with `500` (or logged only under `passive_mode`). See `docs/adapters/decorators.md`.
- `EVENT_ROUTE_UNRESOLVED` (`route_unresolved`) event type.

### Fixed

- Behavioural rules were inert on any adapter that wires its decorator per request. `BehavioralProcessor._behavior_tracker()` read the decorator only from `BehavioralContext`, which adapters snapshot when they construct the middleware — before the application attaches its `SecurityDecorator` — and rebuild only when an agent, OpenTelemetry, Logfire or enrichment is enabled. On a plain decorator-only setup the tracker resolved to `None` on every request, so `usage_monitor`, `return_monitor` and `global_behavior_rules` counted nothing and never banned, throttled or alerted. It now falls back to `request.state.guard_decorator`, the same per-request source `RouteConfigResolver` already uses. Verified end to end: `usage_monitor(max_calls=2, action="ban")` previously served six requests with `200`, and now bans after the threshold. Existing tests missed this because they construct the processor directly with a tracker already attached.

### Behaviour changes

- None by default. `route_resolution_strict` defaults to `False` because guard-core cannot tell a failed match from a request the app simply does not route, so enforcing on every unresolved request would reject those too — with it on, a request to a path the app does not serve returns `500` rather than `404`. Enable it where every reachable path is a known route. Adapters that never set `guard_route_unresolved` are unaffected under either setting.

___

v3.6.0 (2026-07-28)
-------------------

SQL comment-terminator detection (v3.6.0)
------------------------------------------

### Behaviour changes

- Requests carrying a closing quote followed by a SQL comment — `admin'--`, `1'--`, `admin'#`, `admin')--` — are now detected as `sqli` and blocked. Values that previously reached your routes may now be rejected. The match requires the quote and the comment marker to be adjacent (optionally separated by whitespace, `)` or `;`), and `#` must end the value, so quoted fragments such as `querySelector('#app')` and `href='#top'` are unaffected.

### Fixed

- Closed a SQL-injection detection gap: the authentication-bypass form that closes a string literal and comments out the rest of the statement (`WHERE user='admin'--' AND pass='...'`) passed detection. The tautology variants (`' OR '1'='1`) were already covered, but no pattern matched a quote followed by a comment terminator. The attack-simulation baseline is unchanged (`detection_rate` 0.857, `fp_rate` 0.000 across all benign categories).

___

v3.5.0 (2026-07-15)
-------------------

Pipeline factory, decorated-route IP/country enforcement, and detection ReDoS hardening (v3.5.0)
-----------------------------------------------------------------------------------------------

### Breaking changes

- **Global IP and country rules now apply on decorated routes.** Previously, any route carrying per-route decorator config — even one using only `@rate_limit` — silently skipped every global IP allowlist/blocklist and country rule; those global rules now always run on decorated routes, so a client excluded by a global `whitelist` can receive `403` on a decorated route that previously served it. A per-route setting overrides the global gate only for the aspect it explicitly allows, and the IP and country aspects are evaluated **independently**: a route `ip_whitelist` match wins over that route's own `ip_blacklist` (unchanged since v3.2.0) and over the global blacklist, but it does **not** extend to the country aspect — the route's own country rules and the global `blocked_countries` still run. Only an actual route `whitelist_countries` match for the resolved country skips the global country gate. To keep a decorated route reachable by clients outside the global whitelist, give the route its own `ip_whitelist`.
- **A route-level `ip_whitelist` match now grants access only, not trust.** The matched request still passes through rate limiting, user-agent filtering, cloud-provider blocking, and attack-pattern scanning. Previously a route `ip_whitelist` match set `request.state.is_whitelisted=True`, exempting the request from every downstream check — so a route's own `@rate_limit` was silently a no-op for its whitelisted IPs. Global `whitelist` membership still confers full trust; a client in both the global whitelist and a route's `ip_whitelist` is treated as access-only on that route.

### Added

- **`build_default_pipeline()` — one source of truth for the check pipeline.** New `guard_core.core.checks.build_default_pipeline(middleware)` assembles the canonical 17-check pipeline in its defined order. Framework adapters call it instead of hand-listing check classes, so a new engine check reaches every adapter (FastAPI, Flask, Django) without an adapter-side change.
- **Redis resilience settings**: `redis_socket_connect_timeout` (default `2.0`s) and `redis_socket_timeout` (default `2.0`s) bound how long any Redis call can hold a request (both must be positive — `0` would mean a non-blocking socket, not "no timeout"; `None` disables); `redis_health_check_interval` (default `30`s, `0` disables) recycles stale pooled connections; `redis_max_connections` (default `None` = redis-py default) caps the pool; `redis_retries` (default `1`, `0` disables) adds client-level retries with exponential backoff on connection/timeout errors. Note the client-level retry can re-send a non-idempotent `INCR` whose reply was lost after the server committed it, over-counting by one — fail-closed for guard-core's rate-limit counters and self-healing next window.
- **`redis_fail_open`** (`bool`, default `False`): when a Redis outage surfaces as a `GuardRedisError` inside a security check, `fail_secure` governs by default (the request is blocked). Set `True` to skip the failing check and let the request through, treating Redis outages as an availability concern distinct from other check failures.
- **`log_country_check_level`**: per-request country verdicts that are not blocks (whitelisted / not-affected) now log at a configurable level (default `"INFO"`, `None` silences them) via the named `guard_core` logger instead of the root logger. Blocked-country hits still log at `WARNING`; no-rules / no-geolocation cases at `DEBUG`. Penetration-detection hits likewise honour `log_suspicious_level` (previously a second hardcoded-`WARNING` root-logger path), and the remaining bare root-logger calls in `utils.py` / `cloud_handler.py` moved onto named `guard_core` loggers. Async and sync mirrors updated identically.

### Changed

- **Detection regex matching now uses one shared worker pool.** Instead of constructing a thread pool per pattern match, matching uses a single shared executor, and built-in (compile-time-vetted) patterns match directly without the per-match timeout wrapper — only custom and legacy-mode patterns pay that cost. Scan input is now capped to `detection_max_content_length` before matching in every mode, including legacy/no-preprocessor mode, which previously scanned unbounded content (a thread-pool timeout cannot interrupt a regex already running on the interpreter, so the cap bounds the worst case directly). Detection results are unchanged — the attack-simulation baseline (recall 0.857, false-positive rate 0.0) holds bit-for-bit.
- **`add_pattern` now returns `bool`** (`True` registered, `False` rejected) instead of `None`, so callers can distinguish a rejected pattern from a registered one.
- **Cloud-provider IP refresh no longer runs on the request path.** The request that crosses `cloud_ip_refresh_interval` schedules a single-flight background refresh (`cloud_handler.schedule_refresh`) instead of awaiting multi-second provider fetches inline; while one refresh is in flight, further requests are no-ops. The background task runs the middleware's `refresh_cloud_ip_ranges()`, so adapter overrides stay on the periodic path; the debounce timestamp is restored when scheduling fails so the next request retries instead of waiting a full interval; and the in-memory cloud-IP store now honors the refresh TTL, so non-Redis deployments refetch provider ranges each interval instead of caching them for the process lifetime. Async and sync mirrors updated identically.
- **guard-agent's telemetry models are opted out of pydantic plugin instrumentation** at `guard_core` import: `SecurityEvent`/`SecurityMetric`/`EventBatch` set `plugin_settings={"logfire": {"record": "off"}}`, so a host app running `logfire.instrument_pydantic()` no longer emits a span per security event. A model that cannot be force-rebuilt degrades with a logged warning instead of crashing the import.
- **The pipeline handles Redis outages per `redis_fail_open`**: a `GuardRedisError` escaping a check is either skipped with a warning (`redis_fail_open=True`) or handed to the standard `fail_secure` path (default). Async and sync mirrors updated identically.

### Fixed

- **Built-in detection patterns rewritten to close a ReDoS.** Several patterns — SQL `SELECT ... FROM` and `UNION SELECT NULL`, a handful of recon file-extension/source-map/backup patterns, and two XSS patterns — could backtrack super-linearly on crafted input; they now run in linear time, closing a request-triggered ReDoS on the detection path.
- **`build_default_pipeline` now propagates `SecurityConfig.muted_check_logs`** to the pipeline, so muting a check's block/error logs takes effect.
- **Suspicious-pattern registration now rejects unsafe regexes.** `add_pattern` — used when restoring custom patterns from Redis and when applying dynamic-rule pattern pushes — runs each pattern through the ReDoS safety validator before it reaches the live matcher, and no longer logs "Added" for a pattern it rejects. Unsafe or malformed patterns are logged and skipped instead of compiled into the live matcher.
- **The shared regex executor is now initialized under a lock**, closing a first-call race that could leak a worker pool.
- **Custom-pattern safety validation no longer false-rejects safe patterns under scan load.** `validate_pattern_safety` probes now run on a dedicated single-worker validation executor, isolated from the shared scan pool used for live request matching, and elapsed time is measured from when a probe starts executing rather than when it was queued — a busy scan pool can no longer silently drop a pushed dynamic rule or a Redis-restored custom pattern.
- **The shared regex scan pool can no longer be permanently wedged by a slow custom pattern.** Four consecutive timed-out submissions now swap in a fresh pool — the stale pool is shut down non-blocking and a warning names the leaked workers — and the counter resets on any successful scan.
- **The custom-pattern timeout heuristic now honours `detection_compiler_timeout`** (falling back to its 2.0s field default in legacy/no-compiler mode) instead of a hardcoded 2.0s, so tuning the timeout actually changes when a custom pattern is flagged — and logged/reported — as timed out.
- **Registering a custom pattern no longer blocks the event loop.** `add_pattern`'s ReDoS validation (up to ~1s of probes on Redis restore or dynamic-rule push) is now offloaded to a worker thread in the async API; the sync API is unchanged.
- **Pattern timeout heuristics now use a monotonic clock**, so a wall-clock/NTP step can no longer misclassify a match as timed out.
- **`dynamic_rule_violation` is now a registered, mutable event type.** It can be suppressed via `muted_event_types`; it was emitted by endpoint rate limiting but previously rejected by config validation.
- **Banned-IP blocks are now visible to telemetry.** Blocking a banned IP emits an `ip_blocked` event with `filter_type="banned"`; repeat requests from already-banned IPs were previously invisible.
- **`geo_ip_db_max_age` now takes effect.** It is passed to the auto-constructed IPInfo handler; the setting was previously silently inert.

The Redis resilience settings, `redis_fail_open`, `log_country_check_level`, the non-blocking cloud-IP refresh, and the pydantic-instrumentation opt-out were contributed by [@davidsmfreire](https://github.com/davidsmfreire) in [#39](https://github.com/rennf93/guard-core/pull/39).

### Removed

- **Dead `RouteConfig.session_limits`** attribute — never set by any decorator, never read by any check.

___

v3.4.0 (2026-07-02)
-------------------

Body-scan location scoping, recursive/form/multipart detection exclusion, and live detection configuration (v3.4.0)
------------------------------------------------------------------------------------------------------------------

### Added

- **`detection_scan_body` — location-scoped penetration detection.** New `SecurityConfig.detection_scan_body` (`bool`, default `True`), with a per-route override via `RouteConfig.detection_scan_body` and the `detection_exclusion(scan_body=…)` decorator argument. When set to `False`, penetration detection scans the URL path, query parameters, and headers but never reads or matches the request body — removing the entire request-body false-positive class in a single switch, regardless of body shape (JSON, form, multipart), while preserving scanner/recon protection on the URL surface. The default `True` preserves prior behavior. Async and sync mirrors updated identically.

### Changed

- **`excluded_detection_body_fields` now matches nested, form, and multipart bodies.** Previously only top-level JSON keys were excluded, so the allowlist could not reach content nested inside arrays/objects, and non-JSON bodies were scanned as an opaque blob. Excluded field names are now matched at any JSON nesting depth, applied to `application/x-www-form-urlencoded` field names (after decoding), and applied to `multipart/form-data` text-part names (file parts are skipped, never scanned). Bodies that are not structured or not parseable still fall back to a whole-body scan. The allowlist is now effective for OpenAI-style `{"messages":[{"content": …}]}` payloads, HTML form submissions, and small text uploads. Async and sync mirrors updated identically.
- **Detection settings now take effect in production (behavior change).** The suspicious-pattern engine is configured from `SecurityConfig` at middleware startup, so `detection_threat_score_threshold`, the content preprocessor, and the semantic analyzer now apply to live traffic. Previously the process-global detection singleton was constructed once at import with no config and never reconfigured, so those settings were silently inert outside of tests. As a result, detection now runs in its enhanced mode in production: the default `detection_threat_score_threshold` is unchanged (`1.0`), but the content preprocessor (which normalizes and decodes payloads before matching, catching encoded evasion) and the pure-Python semantic analyzer are now active for every request. No new dependencies are required. Review your detection logs after upgrading and tune `detection_threat_score_threshold`, the `excluded_detection_*` sets, or `detection_scan_body` if the tighter matching changes what is flagged. Async and sync mirrors updated identically.

___

v3.3.0 (2026-07-01)
-------------------

Detection overhaul — recall 0.42 → 0.86, false positives 0.125 → 0.0, graduated anomaly scoring, and an attack-simulation benchmark harness (v3.3.0)
--------------------------------------------------------------------------------------------------------------

### Added

- **Graduated anomaly scoring.** New `SecurityConfig.detection_threat_score_threshold` (`float`, default `1.0`, `ge=0.0, le=10.0`): the anomaly score a request must reach before it is flagged as a threat. Detection now accumulates a graduated per-request anomaly score instead of relying on a single binary pattern match. The default threshold of `1.0` reproduces the prior flag-on-any-match behavior, so upgrading is behavior-neutral unless you deliberately raise the threshold (fewer, higher-confidence flags) or lower it (more sensitive). Async and sync mirrors updated identically.
- **Attack-simulation benchmark harness.** A reproducible benchmark (`make attack-sim`) that scores the detector against a labelled corpus of malicious and benign payloads and reports detection (recall) and false-positive rates against a committed `baseline.json`, plus an AI-coordinated red-team campaign generator with verified attack seeds. Test/CI infrastructure only — no runtime or public API surface.

### Changed

- **Detection recall raised from 0.42 to 0.86.** Repaired the content preprocessor's comment stripping — SQL block/line comments and several encoded payload forms were not normalized before pattern matching — and expanded coverage across the suspicious-pattern set, so a large class of previously-missed injection and traversal attempts is now caught. Async and sync mirrors updated identically.
- **False-positive rate reduced from 0.125 to 0.0, with recall held.** Tightened patterns to require genuine attack context instead of matching benign traffic: `SELECT … FROM` is now scored by corroboration rather than a bare keyword, and the `ORDER BY`, DDL, ERB-template, and NoSQL-operator patterns require surrounding attack context. The benign corpus was expanded and the baseline re-measured. Async and sync mirrors updated identically.

### Fixed

- **`ipinfo_token` / `ipinfo_db_path` deprecation warning no longer fires on `None`.** The `DeprecationWarning` added in 3.2.0 keyed only on whether the field was passed to the constructor, so a caller forwarding an optional setting — e.g. `SecurityConfig(ipinfo_token=settings.ipinfo_token)` where the setting may be `None` — received a spurious warning even when ipinfo was not in use. The warning now fires only when the deprecated field has a non-`None` value. Async and sync mirrors updated identically.

___

v3.2.0 (2026-06-23)
-------------------

Cloud-IP region scoping, IP allow-list correctness, bounded body inspection, async/sync mirror parity, agent-error clarity, deprecation signalling, and documented Protocols (v3.2.0)
--------------------------------------------------------------------------------------------------------------

### Added

- **Observable agent and middleware errors.** New `SecurityConfig.on_error` — one best-effort `on_error(stage, exc, context)` hook (`stage` ∈ `agent_init` / `geoip` / `transport_send` / `encryption`) invoked at failure points and guaranteed never to propagate into the request path (a hook that raises is caught and logged). New `SecurityConfig.agent_strict` (default `False`): adapters raise at initialization instead of silently degrading to agent-off when an enabled agent cannot be constructed.
- **Region/scope carve-outs for cloud-IP blocking.** `block_cloud_providers` and `@block_clouds` now accept flat-string region selectors: a bare provider (`"GCP"`) blocks the whole provider unchanged, while a carve-out (`"GCP:!us-central1"`) blocks the provider *except* that region. Region scoping is derived from the real `scope` field in GCP's `cloud.json` and the `region` field in AWS's `ip-ranges.json` (no hardcoded region lists); Azure remains provider-level. The `network`→`region` index is built at refresh/index time so per-request `is_cloud_ip` stays O(current) — a single dict lookup on a match. `block_cloud_providers` is now typed `set[str]` (was `set[CloudProvider]`); existing bare-provider configs are unchanged. Region data survives Redis via inline `"network|region"` encoding under versioned keys (`cloud_ip_v2` / `cloud_ranges_v2`) — pre-upgrade cache entries are ignored and refetched within `cloud_ip_refresh_interval`, and older replicas never read the new value shape during a rolling deploy. Async and sync mirrors updated identically.

- **Bounded request-body inspection.** New `SecurityConfig.detection_max_body_inspect_bytes` (default `262144` / 256 KiB; `ge=1024, le=10485760`). `detect_penetration_attempt` now skips reading and scanning the body when the request's `Content-Length` exceeds the cap, so a large body (e.g. ~300MB on a high-traffic proxy) is no longer fully buffered and decoded into memory on the hot path. This bounds the read itself — unlike `detection_max_content_length`, which only truncates inside the regex preprocessor after the body is already in memory. Async and sync mirrors updated identically.

### Fixed

- **IP allow-list is now reliably honored.** An explicit whitelist match overrides the blacklist (dynamic IP bans, evaluated earlier, still win), applied consistently to the global path (`is_ip_allowed`) and the route path (`check_route_ip_access`) — previously the blacklist was evaluated first, so a whitelisted IP that also fell inside a blacklisted CIDR was blocked. Bare-IP matching now uses parsed `ip_address()` equality instead of raw string comparison, so IPv6 compact and expanded forms (`::1` vs `0:0:0:0:0:0:0:1`) match correctly. The global and route-level matchers share one primitive (`utils._ip_in_list`) so they cannot drift, and precedence is documented in the `SecurityConfig.whitelist` / `blacklist` field descriptions. Sync mirror updated identically.
- **`X-Forwarded-For` client-IP extraction honors `trusted_proxy_depth`.** `_extract_from_forwarded_header` previously returned the leftmost (client-spoofable) `X-Forwarded-For` entry regardless of `trusted_proxy_depth`; it now returns the `trusted_proxy_depth`-th entry from the right, so a client prepending fake entries can no longer defeat the IP allow-list behind trusted proxies.
- **Restored async/sync mirror parity and enforced it in CI.** The generated `guard_core.sync` mirror had drifted from its async source (`make check-sync` was failing across ~33 files). Repaired the `unasync` generator (bare `asyncio.Lock` annotations, `from guard_core.handlers import …` package imports, the `CloudIpStoreFactory` alias, the decorators logger string, and AsyncMock `await_count`/`await_args` assertions) and excluded the genuinely hand-maintained sync files — the `RateLimitManager` threading lock and its tests — that the regex transform cannot reproduce. A new `check-sync` pre-commit hook now fails CI on any future async/sync drift.
- **Clear, actionable error when the agent package is missing.** `SecurityConfig.to_agent_config()` now raises `AgentPackageNotInstalledError` (naming the package and install command) instead of returning an ambiguous `None`, so a missing `guard-agent` can no longer be misreported as an "invalid config / check `agent_api_key`" error by adapters.
- **GeoIP lookups no longer fail silently.** `SecurityEventBus._lookup_country` now logs at warning and fires the `on_error` hook (`stage="geoip"`) instead of swallowing the exception with a bare `except Exception: return None`.
- **Replaced the deprecated redis `setex` call** with `set(..., ex=ttl)` in both the async and sync Redis handlers, clearing the redis-py `DeprecationWarning`.

### Deprecated

- **`ipinfo_token` and `ipinfo_db_path` now signal deprecation at runtime.** Both fields — long described as deprecated in favour of a custom `geo_ip_handler` — now emit a `DeprecationWarning` when explicitly set, raised once at construction from a `model_validator` keyed on `model_fields_set` (so it never fires on the default value or on internal access). Both keep working unchanged; removal is targeted for a future major release. Migrate by passing any `GeoIPHandler` as `geo_ip_handler`.

### Documentation

- **Documented the integrator-facing Protocols.** Every public `Protocol` extension point — `RedisHandlerProtocol`, `AgentHandlerProtocol`, `CloudIpStoreProtocol`, `GeoIPHandler`, `GuardRequest`, `GuardResponse`/`GuardResponseFactory`, `GuardMiddlewareProtocol` (and their `Sync*` mirrors) — now carries a WHAT/WHEN/HOW class docstring plus a per-method contract docstring covering return-value semantics (None-on-miss, None vs empty set, bool success, TTL units). Docstrings only; no signature or behavior change.
- **Added an API-surface audit** (`docs/internals/api-surface-audit.md`): an inventory of all `SecurityConfig` fields and the package exports, grouped by domain with a keep/deprecate/group/remove recommendation per item, the `ipinfo_*` deprecation path, and the guard_core ↔ fastapi-guard export single-source-of-truth.

___

v3.1.1 (2026-05-27)
-------------------

Agent endpoint default + PEP 639 license metadata (v3.1.1)
----------------------------------------------------------

- **Changed** — `SecurityConfig.agent_endpoint` now defaults to `https://api.guard-core.com` (previously `https://api.fastapi-guard.com`), aligning the Guard Agent SaaS endpoint with the guard-core brand. Set `SecurityConfig(agent_endpoint=...)` to target a different host.
- **Packaging** — Migrated license metadata to PEP 639: `license = "MIT"` (SPDX expression) plus `license-files = ["LICENSE"]`, and dropped the deprecated `License :: OSI Approved :: MIT License` classifier. Clears the setuptools `project.license`-table and license-classifier deprecation warnings.
- **Build** — Removed the unused `setup.py`; the release workflow now builds via `python -m build` (hatchling backend) instead of `python setup.py sdist bdist_wheel`, eliminating the `setup.py install is deprecated` warning.

___

v3.1.0 (2026-05-15)
-------------------

Production reliability + ergonomics: NOSCRIPT recovery, lazy_init by default, cloud-IP store factory (v3.1.0)
------------------------------------------------------------------------------------------------------------

### Fixed

- **Recover from Redis NOSCRIPT silently degrading rate limiting.** `RateLimitManager._get_redis_request_count` previously caught `RedisError` and fell through to in-memory counters when EVALSHA raised `NoScriptError` (after `SCRIPT FLUSH`, restart, or failover to a node without our cached SHA), leaving every replica desynchronized. Now catches `NoScriptError` specifically inside the connection block, reloads the Lua script via `script_load`, and retries once. Sync mirror updated identically.
- **Drop log levels for routine private-IP and missing-geo noise.** "IP not geolocated" and "no countries blocked or whitelisted" → `DEBUG`. "Potential IP spoof attempt" → `DEBUG` for private/loopback/link-local source IPs; `WARNING` for public sources.
- **`RedisCloudIpStore` default `key_prefix` no longer duplicates the `guard:` segment.** Default changed from `"guard:cloud_ip"` to `"cloud_ip"` because `RedisManager.set_key` already prepends `config.redis_prefix`.
- **Cloud-provider validation derived from the `CloudProvider` Literal** instead of hardcoded sets.
- **`DynamicRules.blocked_cloud_providers` payloads filter through `VALID_CLOUD_PROVIDERS`** with warning on ignored entries. Sync mirror patched.
- **`@block_clouds` decorator filters unknown cloud providers** instead of silently storing them.
- **`@block_countries` / `@allow_countries` decorators uppercase-normalize ISO codes** to match the geo handler's output. Sync mirror updated.
- **Country normalization in dynamic rules.** `_apply_country_rules` in async + sync `DynamicRuleManager` uppercases inputs and stores `frozenset[str]`.
- **Cloud-IP store class-as-factory resolution.** `HandlerInitializer` now treats a bare class object passed via `cloud_ip_store=RedisCloudIpStore` as a factory and invokes it with `redis_handler`.
- **Lazy-init partial-failure isolation.** `_run_lazy_init` wraps cloud-IP and geo-IP initialization in independent `try` blocks so a cloud failure no longer disables geo init. Important now that `lazy_init=True` is the default.
- **PR #19 fallout cleanup.** Cleared 14 ruff F821/UP037 errors and 5 mypy errors left behind by PR #19.
- **`SecurityConfig.dynamic_rule_interval` is now actually honored.** `to_agent_config()` previously dropped this field on the floor; the agent's `_rules_loop` ran on a hardcoded 300s regardless of what users configured. Fixed by forwarding the value through to `AgentConfig.dynamic_rule_interval`. Effective once `guard-agent >= 2.6.0` is installed.

### Changed

- **`lazy_init` defaults to `True`.** Cloud-IP refresh now runs in a background task; `initialize_redis_handlers` returns immediately. Set `lazy_init=False` to preserve the old synchronous-init behavior.
- **`blocked_countries` and `whitelist_countries` are now `frozenset[str]`.** Pydantic validator accepts list/tuple/set/frozenset and normalizes to uppercase.
- **`SecurityConfig.block_cloud_providers` field annotation now uses `set[CloudProvider] | None`** (the Literal alias) instead of inline `Literal["AWS", "GCP", "Azure"]`.

### Added

- **`cloud_ip_store` accepts a `CloudIpStoreFactory` callable** (`Callable[[RedisHandlerProtocol], CloudIpStoreProtocol]`). Sync mirror exposes `SyncCloudIpStoreFactory`.
- **`CloudProvider` Literal alias and `VALID_CLOUD_PROVIDERS` frozenset** exported from `guard_core.models`.
- **`rate_limit_script_reloaded` SecurityEvent** emitted on NOSCRIPT recovery.
- **`SecurityConfig.agent_status_interval`** — new `int` field (default 300, range 60-86400) controlling how often the agent reports its status to the SaaS dashboard. Forwarded to `AgentConfig.status_interval`. Pairs with `guard-agent >= 2.6.0` which actually honors the value (the agent previously hardcoded 300).

___

v3.0.0 (2026-04-29)
-------------------

Fail-secure by default, broader cloud-provider coverage, agent encryption + version propagation (v3.0.0)
--------------------------------------------------------------------------------------------------------

### Breaking changes

- **`SecurityConfig.fail_secure` now defaults to `True`.** Any unhandled exception inside a security check now blocks the request with HTTP 500 instead of logging the error and falling through. Bugs in checks that previously slipped past as silent fail-open responses now surface immediately. To restore the old behavior on deployments that depend on it, set `fail_secure=False` explicitly:

  ```python
  config = SecurityConfig(fail_secure=False)
  ```

  Recommended migration: keep the new default and fix any check exceptions that surface — the previous default could mask serious bugs.

### Added

- `fetch_digitalocean_ip_ranges()` — pulls the DigitalOcean geofeed CSV from `https://www.digitalocean.com/geo/google.csv` and returns the set of CIDRs (IPv4 + IPv6).
- `fetch_linode_ip_ranges()` — pulls the Linode/Akamai RFC8805 CSV from `https://geoip.linode.com/`.
- `fetch_vultr_ip_ranges()` — pulls the Vultr/Constant geofeed JSON from `https://geofeed.constant.com/?json`.
- All three providers wired into `_ALL_PROVIDERS`, the `CloudManager` singleton initializer, and the three provider→fetcher dispatch maps (`_refresh_providers`, `refresh_async`, `_refresh_providers_via_redis_handler`). Sync mirrors updated in lockstep using `requests` instead of `aiohttp`.
- Each fetcher gracefully returns an empty `set()` on any HTTP / parse failure with `logging.error(...)`. Malformed CIDR rows in CSV feeds are skipped silently rather than discarding the entire feed.
- **`SecurityConfig.agent_project_encryption_key: str | None`** — per-project AES-256-GCM key the framework adapter passes through to the agent. When set, the agent posts to `/api/v1/events/encrypted` with the encrypted payload; when `None`, the agent uses the plaintext ingest path. Required for any API key whose SaaS-side configuration enforces payload encryption — without it the SaaS rejects every batch and the agent's ingestion breaker stays tripped. `to_agent_config()` propagates this directly to `AgentConfig.project_encryption_key`.
- **`SecurityConfig.agent_guard_version: str | None`** — framework wrapper version (e.g. `fastapi_guard.__version__`) propagated to the agent so the SaaS can attribute telemetry to the wrapper version, not just the agent version. `to_agent_config()` propagates this to `AgentConfig.guard_version`. Pairs with `guard-agent >= 2.4.0`'s `EventBatch.guard_version` field; older agents silently drop the kwarg via Pydantic's default `extra='ignore'`.

### Notes

- Alibaba was evaluated for inclusion but no reliable official public IP-range feed could be confirmed. Deferred to a follow-up rather than ship a guessed URL.

___

v2.2.2 (2026-04-29)
-------------------

Safer failures, observability, and truthful copy (v2.2.2)
---------------------------------------------------------

- **Fixed** — Decode iteration cap raised from 3 to 7 in `ContentPreprocessor.decode_common_encodings` to cover up to 7-layer polyglot encoding evasion (`base64(base64(base64(base64(payload))))` and similar). The loop still terminates on `if content == original: break`, so it stays bounded. Sync mirror updated in lockstep.
- **Fixed** — `IPInfoManager.get_country` no longer raises `RuntimeError("Database not initialized")` when the MaxMind reader is unset; it now logs a WARNING and returns `None`. Callers no longer need to wrap every geo lookup in a defensive `try/except`. Sync mirror.
- **Fixed** — `ErrorResponseFactory.apply_modifier` catches exceptions raised by the user-supplied `custom_response_modifier`, logs via `logger.exception`, and returns the unmodified response. A buggy modifier can no longer crash the request pipeline. Sync mirror.
- **Added** — `IPBanManager.banned_ips` is now an `_ObservableTTLCache` that exposes `evictions_count` on the manager and emits a WARNING every 100 overflow evictions. Only overflow evictions are counted; TTL-expiry deletions are excluded (verified against `cachetools` source — `expire()` uses `Cache.__delitem__`, not `popitem`). Sync mirror.
- **Added** — `HandlerInitializer.initialize_dynamic_rule_manager` emits a WARNING when `enable_dynamic_rules=True` but no agent handler is reachable, so the silent fall-back to static config is now visible to operators. The opt-out path (`enable_dynamic_rules=False`) remains silent. Sync mirror.
- **Changed** — README and CHANGELOG copy aligned with what the engine actually does. Replaced "intelligent / behavioral analysis / anomaly detection / penetration detection" framing with signature-based detection plus multi-metric semantic scoring. Added a "How Detection Works" section to the README walking through the decode → regex match → semantic-score → ReDoS-guard pipeline.

___

v2.2.1 (2026-04-27)
-------------------

RedisManager singleton hardening (v2.2.1)
-----------------------------------------

- **Fixed** — `RedisManager.__new__` always created a new instance and overwrote the class-level `_instance` reference, breaking the singleton contract. When middleware or a fixture called `RedisManager(config)` more than once, each successive call orphaned the previous instance — but each instance owned an independent `_redis` connection set by its own `initialize()`. The orphaned connection had no closer; on garbage collection it surfaced as `ResourceWarning: unclosed Connection` (and the underlying socket / asyncio transport). Under `pytest -W error` this manifested as cascading `PytestUnraisableExceptionWarning` failures across any test suite that constructed `RedisManager` more than once.
- `__new__` now follows the same true-singleton pattern as `RateLimitManager`: create the instance once, update `config` on every call, return the same instance. Connections are owned by a single live instance and `close()` actually closes them.
- Mirror fix applied to `guard_core.sync.handlers.redis_handler.RedisManager`.
- No behavior change for production callers that construct `RedisManager` once at startup. Test suites that previously leaked redis connections across fixtures now run clean under `-W error`.

___

v2.2.0 (2026-04-26)
-------------------

Phase 1 hardening — CORS, fail-secure, CIDR bans, preprocessor fixes, concurrency safety
------------------------------------------------------------------------------------------

### Added

- `guard_core.handlers.cors_handler` — framework-agnostic CORS preflight + response-header module consumed by every adapter. Provides `CorsHandler`, `CorsPreflightResponse`, and `is_preflight`.
- `SecurityConfig.fail_secure` field (default `False`) — when `True`, an unhandled exception in any check blocks the request instead of falling through.
- `IPBanManager.ban_ip` accepts CIDR networks (`10.0.0.0/24`, `2001:db8::/32`) for both IPv4 and IPv6. Invalid networks raise `ValueError`.
- Preprocessor encoding decoders: base64 (length-bounded), `\xNN` hex, and `\uNNNN` JS unicode escapes are decoded inside the existing 3-iteration loop.
- Preprocessor SQL comment stripping: case-aware in-keyword comment removal (`SELE/**/CT` → `SELECT`, `sele/**/ct` → `select`) plus space-replacement for between-token cases (`1/**/OR` → `1 OR`). Line comments (`--`, `#`) replaced with whitespace.

### Fixed

- `<?php` attack-indicator regex now matches the literal PHP open tag (was `<?php` which made `<` optional and matched any string containing `php`). #6
- Truncated preprocessor output now interleaves attack regions and gaps in source order (was reversing gaps via `insert(0, ...)`). #7
- `fail_secure` is now actually enforceable; the previous `hasattr` guard always returned `False` because the field was undeclared on `SecurityConfig`.
- Compiled-regex cache key is deterministic (`{pattern}:{flags}`) instead of using process-salted Python `hash()`, eliminating cross-pattern collisions.
- Sync `RateLimitManager` serializes in-memory state with `threading.Lock`, avoiding `RuntimeError: deque mutated during iteration` under multi-threaded WSGI servers.
- `IPBanManager.ban_ip` refuses ban durations longer than the local cache TTL when Redis is unavailable; raises `ValueError` instead of silently truncating to one hour.
- `DynamicRuleHandler._apply_rules` snapshots config before mutating and rolls back on exception. Concurrent rule pushes serialize under a lock (`asyncio.Lock` async, `threading.Lock` sync).

### Internal

- Test infrastructure: `tests/test_decorators/test_behavior_handler.py` and `tests/test_sync/test_decorators/test_behavior_handler.py` now correctly close their Redis connections in teardown (previously leaked, surfacing as `ResourceWarning` errors under `-W error`).

___

v2.1.0 (2026-04-25)
-------------------

lazy_init: background warmup instead of first-request stall
-----------------------------------------------------------

### Changed

- `lazy_init=True` now schedules the IPInfo MMDB download and cloud-IP provider fetches as a background task during `initialize_redis_handlers()`, instead of triggering them synchronously on the first request that needs them. Eliminates the multi-second latency spike on the first user request. During the warmup window (typically a few seconds at startup), cloud-provider blocking and country-based geo checks are inert; rate limiting, IP banning, pattern detection, and all other security layers remain fully active. After the background task completes, the geo/cloud layers activate seamlessly.
- `HandlerInitializer` exposes `_lazy_init_task`, the `asyncio.Task` (or `threading.Thread` in the sync mirror) that runs the deferred cloud and geo bootstrap when `lazy_init=True`. Failures inside the background task are caught and logged via `logging.getLogger("guard_core.core.initialization")` (`guard_core.sync.core.initialization` for the sync mirror) at `WARNING` level; they never propagate.
- `CloudIpRefreshCheck.check()` no longer triggers a synchronous `cloud_handler.refresh_async(...)` when ranges are empty under `lazy_init=True`. The interval-based scheduled refresh path is now the only refresh path inside the request lifecycle.

### Compat notes

- `lazy_init=False` (the default) is unchanged — eager init at startup.
- Users who opted into `lazy_init=True` in 2.0.0 see only an upside: the first-request latency that 2.0.0 imposed is replaced with a brief startup-time warmup window where cloud/geo layers are inert. No code changes required.
- `lazy_init=True` users with strict cloud-provider blocking who can't tolerate any warmup window should stay on `lazy_init=False` (or continue using `lazy_init=True` with a Kubernetes/ALB warmup probe that hits a health endpoint before real traffic). As of v3.8.0, your adapter's status surface (fastapi-guard: `GET /_guard/status` or `SecurityMiddleware.get_initialization_status()`) is what that health endpoint should read — see [Provider Status](configuration/security-config.md#provider-status).

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
- **Deterministic threat score.** `ThreatScorer.score_for(event_type)` maps 16 event types to 0-100 scores defined in guard-core's `_THREAT_SCORE_MAP` (`penetration_attempt=90`, `ip_banned=70`, medium events=50, `rate_limited=20`, default=20). No ML, no server-side recomputation.
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
