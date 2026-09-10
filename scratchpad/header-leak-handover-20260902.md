# Handover: raw request headers logged on every block (found 2026-09-02)

Source of truth is the installed 3.17.0 wheel, paths relative to `guard_core/`:

- `_utils/request_logging.py:24` - `_extract_request_context` puts `dict(request.headers)` into the context.
- `_utils/request_logging.py:31` (request), `:45` and `:53` (suspicious), `:63` (generic) - every message builder appends `Headers: {context['headers']}`.
- `log_suspicious_level` defaults to `WARNING` (`_security_config_fields.py:277-279`), so every active-mode block logs the headers by default. `log_request_level` defaults to `None`, so per-request logging is off unless enabled, then it logs headers on every request.
- No redaction anywhere: `grep -rniE "redact|mask" guard_core/*.py` is empty. `agent_sensitive_headers` (`_security_config_fields.py:647`) is only forwarded to `AgentConfig` (`models.py:323`), never consulted by `log_activity`.
- 3.15.0's `_YieldToHostRootHandlers` (`_utils/logging_utils.py:57-58`) sends the same line into the host app's root handlers, so it lands in the consumer's own log file too.

Repro (Vexa gateway image on 3.17.0, `GUARD_ENABLED=true GUARD_IP_BLACKLIST=0.0.0.0/0`):

```text
curl -H 'X-API-Key: sekrit-vexa-key-123' http://127.0.0.1:8000/health
# container log:
[guard_core] ... WARNING - Suspicious activity detected from 192.168.65.1: GET .../health - Reason: IP not allowed ... - Headers: {'host': ..., 'x-api-key': 'sekrit-vexa-key-123', ...}
```

Odysseus perimeter under TestClient showed `'authorization': 'Bearer ...'` and `'cookie': 'session=...'` the same way.

Consumers waiting on the patch:

- Vexa-ai/vexa#1324: lock at 3.17.0 (`core/gateway/services/gateway/uv.lock`), bump with `uv lock --upgrade-package guard-core`.
- odysseus-dev/odysseus#6193: floor `guard-core>=3.17.0` in `requirements-optional.txt`; the follow-up PR comment for the 3.17.0 bump was drafted and deliberately not posted, to post once with the 3.17.1 floor.
