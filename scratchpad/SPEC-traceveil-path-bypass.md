# SPEC: callable path bypass (Traceveil integration)

Status: DRAFT, build held until Nafez finalizes Traceveil's side. Target: guard-core 3.17.0. No adapter version pins.

## Problem

Traceveil (Nafez's per-request tracer, github pending) mounts its own routes (`/traceveil`, `/traceveil/api`) in the host app. App-level middleware, including Guard, must skip those paths. Traceveil exposes:

```python
bypass_paths = configure_traceveil(app, store, ignore_paths=[...], ...)
# bypass_paths: Callable[[str], bool]
```

Guard has no callable-shaped bypass today. `exclude_paths` is deliberately a partial exclusion, not a full bypass; full bypass is route-config only (`bypassed_checks`). This spec adds the callable seam.

## Design

### Config surface

`SecurityConfig`:

```python
path_bypass_checks: list[Callable[[str], bool]] = []
```

- List, not single callable: mirrors Nafez's own middleware shape (`skip_paths: list[SkipPath]`) and costs nothing.
- Validation at model level (same lesson as `bypass()` token drift): every entry must be callable, else `ConfigError`. No silent acceptance, no warning-only.

### Evaluation point (verified against `core/checks/pipeline.py`)

Inside `SecurityCheckPipeline.execute()`, after the timing stash is set (`request.state._guard_pipeline_start`, needed by response-side metrics) and before the check loop. Concretely: after `_rebuild_if_stale()` (so a config mutation swapping the callable list is picked up on the very next request) and after `exclusion_scoped` is read. On match: fire the middleware event (`action_taken="path_bypass"`, reason, path), then `return None`. No check runs.

Two interactions the read surfaced:

- `exclusion_scoped` requests normally still run checks with `enforced_on_excluded_paths=True`. Bypass wins over that too: a bypassed path runs no check at all. Document it.
- The path form guard already uses everywhere in the pipeline is `request.url_path` (`_log_extra`, rebuild error logging). The bypass callables receive that same string, which resolves half of open question 1 before Nafez answers it: his matcher receives the same form as everything else in the pipeline.

### Callable contract

- Signature `(path: str) -> bool`, sync only. Works in both ASGI and WSGI trees, so the unasync mirror needs no special casing.
- Guard passes the same path string it uses for route resolution. Exact form (raw scope path vs normalized) is open question 1.

### Explicitly out of scope

- No path pattern matching on guard's side. Guard only invokes the callables.
- No change to `exclude_paths` semantics.
- No `on_block`-style payload on bypass. Bypass is not a block. If Nafez wants bypass events in his trace store he reads the event/log (open question 4).
- No pinning of any bypass shape as "intended" in tests.

## Open questions (gate on Nafez's side)

1. Exact path form: does `bypass_paths` match on the raw ASGI scope path, and is the match exact-only or prefix? Prefix matching must be prefix-proof (`/traceveil` must not match `/traceveil-evil`). Guard's contract is "we pass the path, you decide", but we should document which path form we pass.
2. Auth: with guard skipping auth on those routes, Traceveil owns authn/authz for its own dashboard. Confirm that is his position.
3. Should the bypass evaluation run before or after route-config extraction in the pipeline? (Route-config extraction is check 1; a bypassed path probably should not pay for it, but confirm there is no ordering dependency.)
4. Does he want a programmatic bypass event (like `on_block`) `on_block`-style payload, or is the middleware event/log line enough?
5. His sync tracing trade-off: if it interacts with threadpool endpoints, WSGI adapters (Flask/Django) may need the answer too.

## Testing (target: 100% branch + line on every touched file)

- Non-callable entry rejected with ConfigError (root cause of the old bypass() drift, do not repeat it).
- Match: pipeline short-circuits, event fired, no check executes (assert via check spy that earlier checks never ran).
- No match: pipeline behaves identically to today.
- Multiple callables, first-match short-circuit.
- Bypass overrides `exclusion_scoped`: a `enforced_on_excluded_paths=True` check does not run on a bypassed path.
- Sync tree parity via unasync, wire-entry style: path delivered through the real pipeline entry, not a sub-component call.
- No warning filters, no noqa. Zero new warnings.

## Quality gates

Full suite green before any claim: ruff format/check, mypy, xenon, radon, bandit, vulture, pytest, plus Docker/CI verification (not macOS-only).
