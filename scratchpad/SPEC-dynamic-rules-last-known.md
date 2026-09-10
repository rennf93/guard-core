# SPEC: last-known dynamic rules persistence

Status: APPROVED by Renzo 2026-09-01. Rulings below. Independent of the Traceveil spec; separate release.

## Problem

`DynamicRuleManager` (`guard_core/handlers/dynamic_rule_handler.py`) keeps `current_rules` in memory only. A SaaS outage mid-run is survivable: the update loop logs the failure and retries. The real loss is a process restart while the SaaS is down: restart with no fetch success means base config (no dynamic rules) until the SaaS recovers. 2026-09-01 Cloudflare outage was the argument.

## Design

Persist the last successfully applied `DynamicRules` to durable storage on every apply (`_apply_rules` success path, alongside `self.current_rules = rules`), and hydrate from it at `initialize_agent()` time before the update loop starts, so a restart during an outage comes up with the last-known rules instead of base config.

Rules on the hydrate path:

- Respect `expires_at` exactly as `_reject_if_already_expired` does: an expired snapshot is discarded, base config runs. No "stale but keep it" mode without Renzo's explicit ruling.
- Hydrate through the normal apply path (`_apply_rules`), not direct config mutation, so snapshot/restore bookkeeping stays consistent.
- First successful SaaS fetch supersedes the hydrated state via the existing `_should_update_rules` version check. No new conflict logic.

## Renzo's rulings (2026-09-01)

1. Storage: Redis when a redis_handler is present; local JSON file as opt-in fallback when Redis is not available. Read order at startup: Redis first, then file (Redis can lose data independently of the SaaS, so the file stays valuable even with Redis present). Write: Redis always when available, file only when `dynamic_rules_cache_path` is configured.
2. Hydration: unconditional when dynamic rules are enabled. Hydrate at `initialize_agent()` before the update loop starts, through the normal apply path.
3. Version skew / malformed payload: hard-fail to base config. Unknown schema or corrupt data is discarded with an error logged; nothing warn-and-apply.

## Testing

- Apply persists; restart with SaaS down hydrates and applies last-known rules.
- Expired snapshot discarded, base config runs.
- No snapshot / corrupt snapshot / unknown schema: clean base config, error logged, no exception escaping init.
- Hydrated state superseded by first successful fetch.
- 100% branch + line, full quality suite, Docker/CI verification.
