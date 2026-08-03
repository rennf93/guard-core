# Security Pipeline

`SecurityCheckPipeline` (`guard_core/core/checks/pipeline.py`) is a chain of responsibility. Checks run sequentially in insertion order; the first returning a non-`None` `GuardResponse` short-circuits and blocks.

## Execution semantics

* `check.check(request) -> GuardResponse | None`: `None` passes, a `GuardResponse` blocks.
* On a check exception, the pipeline catches it. `fail_secure=True` (default) blocks with HTTP 500 via `check.create_error_response(500, ...)`; `fail_secure=False` continues to the next check.
* All checks returning `None` means the request is allowed (pipeline returns `None`).

## The 17 checks in order

1. `route_config` — extract per-route config.
2. `emergency_mode` — block-all toggle.
3. `https_enforcement` — redirect/reject non-HTTPS.
4. `request_logging` — structured access logging.
5. `request_size_content` — size and content-type gates.
6. `required_headers` — presence checks.
7. `authentication` — auth gate.
8. `referrer` — referrer policy.
9. `custom_validators` — user-supplied sync/async validators.
10. `time_window` — time-of-day access windows.
11. `cloud_ip_refresh` — refresh cloud IP ranges.
12. `ip_security` — whitelist/blacklist + country.
13. `cloud_provider` — block AWS/GCP/Azure source IPs.
14. `user_agent` — UA allow/block.
15. `rate_limit` — sliding window (memory or Redis).
16. `suspicious_activity` — detection engine integration.
17. `custom_request` — user-supplied request-level check.

## Extending

Subclass `SecurityCheck` (`guard_core/core/checks/base.py`), implement `check_name` and `async check(request)`, and append via `pipeline.add_check(...)` or `insert_check(index, ...)`. You get `self.middleware`, `self.config`, `self.logger`, `send_event(...)`, `create_error_response(...)`, and `is_passive_mode()` for free. Do not mutate handlers directly; read/write through `self.config`.

## Pipeline management

`add_check`, `insert_check`, `remove_check(check_name) -> bool`, `get_check_names() -> list[str]`, `__len__`. The shipping adapters construct `SecurityCheckPipeline(checks)` without `muted_check_logs`, so pipeline-level block/error log lines are not muted even when `muted_check_logs` is set; the in-check `log_activity()` calls are muted.