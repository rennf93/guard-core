# Security Pipeline

`SecurityCheckPipeline` (`guard_core/core/checks/pipeline.py`) is a chain of responsibility. Checks run sequentially in insertion order; the first returning a non-`None` `GuardResponse` short-circuits and blocks.

## Execution semantics

* `check.check(request) -> GuardResponse | None`: `None` passes, a `GuardResponse` blocks.
* On a check exception, the pipeline catches it. `fail_secure=True` (default) blocks with HTTP 500 via `check.create_error_response(500, ...)`; `fail_secure=False` continues to the next check.
* All checks returning `None` means the request is allowed (pipeline returns `None`).

## The check catalogue, in order

`DEFAULT_CHECK_CLASSES` (`guard_core/core/checks/factory.py`) names 17 checks. This is the full catalogue and its order is fixed; what a given deployment actually builds is a subset, decided at pipeline-build time (see "Which checks get built" below).

1. `route_config` - extract per-route config.
2. `emergency_mode` - block-all toggle.
3. `https_enforcement` - redirect/reject non-HTTPS.
4. `request_logging` - structured access logging.
5. `request_size_content` - size and content-type gates.
6. `required_headers` - presence checks.
7. `authentication` - auth gate.
8. `referrer` - referrer policy.
9. `custom_validators` - user-supplied sync/async validators.
10. `time_window` - time-of-day access windows.
11. `cloud_ip_refresh` - refresh cloud IP ranges.
12. `ip_security` - whitelist/blacklist + country.
13. `cloud_provider` - block AWS/GCP/Azure source IPs.
14. `user_agent` - UA allow/block.
15. `rate_limit` - sliding window (memory or Redis).
16. `suspicious_activity` - detection engine integration.
17. `custom_request` - user-supplied request-level check.

## Which checks get built

`SecurityCheck.applies_to(cls, config, route_configs) -> bool` (`guard_core/core/checks/base.py`) is a classmethod extension point: given the effective `SecurityConfig` and the collection of registered `RouteConfig`s (or `None` when they cannot be enumerated), it declares whether the check can ever fire. The base implementation always returns `True`, so a check that does not override it runs unconditionally; a check opts into elimination by overriding `applies_to` to return `False` under some condition. `build_default_pipeline(middleware)` (`guard_core/core/checks/factory.py`) filters `DEFAULT_CHECK_CLASSES` through `applies_to` before instantiating anything, so an eliminated check is never constructed, and for the checks that moved their handler import into `__init__` (`ip_security`, `suspicious_activity`, `cloud_provider`, `cloud_ip_refresh`), never imports its handler either.

Elimination is strictly an optimization, never a security decision: every `applies_to` implementation is written to return `True` on any uncertainty, and the one check that reads mutable ban state is pinned to always-keep (below). A default `SecurityConfig()` with no route decorators registered builds exactly four checks: `route_config`, `ip_security`, `rate_limit`, `suspicious_activity`. A configuration that enables every feature builds all 17, in the order above.

Three rules govern the subsetting:

* **`enable_dynamic_rules=True` keeps every dynamically-mutable check regardless of other flags.** `DynamicRuleManager` can mutate `emergency_mode`, `block_cloud_providers`, `blocked_user_agents`, `enable_penetration_detection`, `enable_ip_banning`, and `enable_rate_limiting` at runtime (`guard_core/handlers/dynamic_rule_handler.py`), so `emergency_mode`, `cloud_ip_refresh`, `cloud_provider`, `user_agent`, `rate_limit`, and `suspicious_activity` all OR in `config.enable_dynamic_rules` inside their `applies_to`, and are kept whenever it is set even with every other relevant flag off.
* **Unknown route configuration means keep everything route-driven.** `_collect_route_configs` (`guard_core/core/checks/factory.py`) returns `None`, not an empty tuple, when the middleware has no `guard_decorator` to enumerate. `route_config_applies` (`guard_core/core/checks/helpers.py`) treats `None` as "keep the check" and an empty tuple as "no route declares this, drop it." A middleware that cannot expose its decorator handle loses the optimization on every route-driven check but never loses the protection.
* **`IpSecurityCheck` never overrides `applies_to`**, so it is always built. It fronts an unconditional ban lookup whose store (`ip_ban_manager`) is writable from behavior-rule bans and from other processes sharing the same Redis; no configuration can prove that store will stay empty, so it is never a candidate for elimination.

## Extending

Subclass `SecurityCheck` (`guard_core/core/checks/base.py`), implement `check_name` and `async check(request)`, and append via `pipeline.add_check(...)` or `insert_check(index, ...)`. You get `self.middleware`, `self.config`, `self.logger`, `send_event(...)`, `create_error_response(...)`, and `is_passive_mode()` for free. Do not mutate handlers directly; read/write through `self.config`. A subclass inherits the base `applies_to` (always `True`) unless it overrides it; only override it if the check should participate in `build_default_pipeline`'s elimination.

## Pipeline management

`add_check`, `insert_check`, `remove_check(check_name) -> bool`, `get_check_names() -> list[str]`, `__len__`. `build_default_pipeline` passes `config.muted_check_logs` into `SecurityCheckPipeline`, so both the pipeline-level block/error log lines and the in-check `log_activity()` calls honor `muted_check_logs`; only an adapter that hand-builds `SecurityCheckPipeline(checks)` without going through the factory would need to pass `muted_check_logs` itself.
