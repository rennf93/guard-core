# Modular Architecture Phase 0 + Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the seven standalone Phase 0 defect fixes from the approved modular-architecture spec (`docs/superpowers/specs/2026-07-11-modular-architecture-design.md` §3.4/§5) plus Phase 1: a `build_default_pipeline()` factory in guard-core consumed by fastapi-guard.

**Architecture:** Every task is a self-contained fix or additive API on current `master`; no module system yet. Tasks 1–7 live in guard-core, Task 8 in fastapi-guard. Tasks 2 and 3 both edit `ip_security.py` and MUST run in order.

**Tech Stack:** Python 3.10+, Pydantic v2, pytest (asyncio_mode=auto), uv, unasync sync-mirror.

## Global Constraints

- **NEVER `git commit`, NEVER `git push`.** At each task's final step: `git add` the exact files, then OUTPUT the commit message as text for the maintainer to apply. This overrides any commit instruction in any skill.
- **NO code comments.** Repo rule. Function names carry the documentation.
- **100% line AND branch coverage on every file touched.** Verify with the coverage command in each task.
- **Zero warnings** in pytest output. Never add `filterwarnings` ignores. Expected `DeprecationWarning`s must be captured with `pytest.warns`.
- **Sync mirror:** after ANY change under `guard_core/` or `tests/` (excluding `tests/test_sync/`), run `make sync` then `make check-sync` from repo root. Never hand-edit `guard_core/sync/**` or `tests/test_sync/**` — they are generated.
- **Test names describe behavior**, never process (no "gaps", "final", "coverage" names).
- **Test commands** (guard-core repo root, Redis must be running locally — `docker compose up -d redis` if not):
  - Targeted: `REDIS_URL=redis://localhost:6379 uv run pytest <path>::<test> -v`
  - Full gate per task: `make local-test` (full suite + coverage) — must pass before a task is complete.
  - Quality per task: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core`
- **CHANGELOG.md**: each behavior-affecting task adds its entry under `## [Unreleased]` (create the section if absent), Keep-a-Changelog style, human tone, no AI mentions, no dependency-noise.
- **Attack-simulation baseline must not regress** (Task 6 gate): `REDIS_URL=redis://localhost:6379 uv run pytest tests/attack_simulation/ -q` must pass.
- guard-core paths below are relative to `/Users/renzof/Documents/GitHub/ZZZ/guard-core`, fastapi-guard paths to `/Users/renzof/Documents/GitHub/ZZZ/fastapi-guard`.

---

### Task 1: Register `dynamic_rule_violation` as an event type and replace literal event strings with constants

**Files:**
- Modify: `guard_core/core/events/event_types.py`
- Modify: `guard_core/core/checks/implementations/rate_limit.py:4,69`
- Modify: `guard_core/core/checks/implementations/user_agent.py:3,47`
- Modify: `guard_core/core/checks/implementations/emergency_mode.py:1-4,35`
- Modify: `guard_core/core/checks/implementations/request_size_content.py:1-5,37,79`
- Modify: `guard_core/core/checks/implementations/custom_request.py:1-3,18`
- Modify: `CHANGELOG.md`
- Test: `tests/test_models/test_muted_event_types.py` (create if `tests/test_models/` has no such file; if the directory doesn't exist, create `tests/test_models/__init__.py` empty only if sibling test dirs have one — check `ls tests/test_decorators/` first and mirror)

**Interfaces:**
- Produces: constant `EVENT_DYNAMIC_RULE_VIOLATION = "dynamic_rule_violation"` in `guard_core.core.events.event_types`, member of `EVENT_TYPE_VALUES`. Wire values of all events are UNCHANGED.

- [ ] **Step 1: Write the failing test**

```python
from guard_core.models import SecurityConfig


def test_dynamic_rule_violation_accepted_as_muted_event_type() -> None:
    config = SecurityConfig(muted_event_types={"dynamic_rule_violation"})
    assert "dynamic_rule_violation" in config.muted_event_types
```

- [ ] **Step 2: Run test to verify it fails**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_models/test_muted_event_types.py -v`
Expected: FAIL with `pydantic_core._pydantic_core.ValidationError` mentioning invalid muted_event_types (`dynamic_rule_violation` not in EVENT_TYPE_VALUES).

- [ ] **Step 3: Add the constant**

In `guard_core/core/events/event_types.py`, after line 15 (`EVENT_DYNAMIC_RULE_APPLIED = "dynamic_rule_applied"`), add:

```python
EVENT_DYNAMIC_RULE_VIOLATION = "dynamic_rule_violation"
```

And inside `EVENT_TYPE_VALUES`, after the `EVENT_DYNAMIC_RULE_APPLIED,` entry, add:

```python
        EVENT_DYNAMIC_RULE_VIOLATION,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_models/test_muted_event_types.py -v`
Expected: PASS

- [ ] **Step 5: Replace the five literal sites with constants (wire values unchanged)**

`rate_limit.py` — extend the existing import (line 4):

```python
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_DYNAMIC_RULE_VIOLATION,
)
```

and at line 69 replace `"dynamic_rule_violation",` with `EVENT_DYNAMIC_RULE_VIOLATION,`.

`user_agent.py` — extend the existing import (line 3):

```python
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_USER_AGENT_BLOCKED,
)
```

and at line 47 replace `event_type="user_agent_blocked",` with `event_type=EVENT_USER_AGENT_BLOCKED,`.

`emergency_mode.py` — add import after line 1:

```python
from guard_core.core.events.event_types import EVENT_EMERGENCY_MODE_BLOCK
```

and at line 35 replace `event_type="emergency_mode_block",` with `event_type=EVENT_EMERGENCY_MODE_BLOCK,`.

`request_size_content.py` — add import after line 1:

```python
from guard_core.core.events.event_types import EVENT_CONTENT_FILTERED
```

and at BOTH lines 37 and 79 replace `event_type="content_filtered",` with `event_type=EVENT_CONTENT_FILTERED,`.

`custom_request.py` — add import after line 1:

```python
from guard_core.core.events.event_types import EVENT_CUSTOM_REQUEST_CHECK
```

and at line 18 replace `event_type="custom_request_check",` with `event_type=EVENT_CUSTOM_REQUEST_CHECK,`.

Keep each file's import block alphabetically sorted (ruff `I` rule enforces it — run `uv run ruff format` + `uv run ruff check --fix` after editing).

- [ ] **Step 6: Regenerate sync mirror and run gates**

Run: `make sync && make check-sync`
Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/ -q -x --ignore=tests/attack_simulation`
Expected: all pass (existing tests assert wire strings, which are unchanged).
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core`
Expected: clean.
Run: `make local-test`
Expected: PASS, coverage 100%.

- [ ] **Step 7: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Fixed`:

```markdown
- Registered `dynamic_rule_violation` as a first-class event type; it can now be muted via `muted_event_types` (was rejected by validation despite being emitted by endpoint rate limiting).
```

```bash
git add guard_core/core/events/event_types.py guard_core/core/checks/implementations/rate_limit.py guard_core/core/checks/implementations/user_agent.py guard_core/core/checks/implementations/emergency_mode.py guard_core/core/checks/implementations/request_size_content.py guard_core/core/checks/implementations/custom_request.py tests/test_models/test_muted_event_types.py CHANGELOG.md guard_core/sync tests/test_sync
```

Report commit message for the maintainer (do not commit):
`fix(events): register dynamic_rule_violation event type, use constants for emitted event names`

---

### Task 2: Emit an `ip_blocked` event when a banned IP is blocked

**Files:**
- Modify: `guard_core/core/checks/implementations/ip_security.py:19-45`
- Modify: `CHANGELOG.md`
- Test: `tests/test_core/test_ip_security_banned_ip_events.py` (create)

**Interfaces:**
- Consumes: `EVENT_IP_BLOCKED` (already imported in `ip_security.py:5`).
- Produces: banned-IP blocks now call `event_bus.send_middleware_event(event_type=EVENT_IP_BLOCKED, ..., filter_type="banned")`. Later tasks don't depend on it.

- [ ] **Step 1: Write the failing test**

Create `tests/test_core/test_ip_security_banned_ip_events.py` (fixtures mirror `tests/test_core/test_ip_security_edge_cases.py:11-43`):

```python
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.passive_mode = False
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


@pytest.fixture
def ip_security_check(mock_middleware: Mock) -> IpSecurityCheck:
    return IpSecurityCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    return request


async def test_banned_ip_block_emits_ip_blocked_event(
    ip_security_check: IpSecurityCheck, mock_request: Mock
) -> None:
    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban_mgr,
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        mock_ban_mgr.is_ip_banned = AsyncMock(return_value=True)
        result = await ip_security_check.check(mock_request)

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"
    assert event_call.kwargs["filter_type"] == "banned"
    assert event_call.kwargs["ip_address"] == "1.2.3.4"


async def test_banned_ip_in_passive_mode_emits_logged_only_event(
    ip_security_check: IpSecurityCheck,
    mock_request: Mock,
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True
    with (
        patch(
            "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban_mgr,
        patch("guard_core.core.checks.implementations.ip_security.log_activity"),
    ):
        mock_ban_mgr.is_ip_banned = AsyncMock(return_value=True)
        await ip_security_check._check_banned_ip(mock_request, "1.2.3.4", None)

    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["action_taken"] == "logged_only"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_core/test_ip_security_banned_ip_events.py -v`
Expected: FAIL — `send_middleware_event.await_args` is `None` (no event emitted today).

- [ ] **Step 3: Implement**

In `guard_core/core/checks/implementations/ip_security.py`, inside `_check_banned_ip`, insert between the `log_activity(...)` call (ends line 37) and the `if not self.config.passive_mode:` (line 39):

```python
        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Banned IP attempted access: {client_ip}",
            ip_address=client_ip,
            filter_type="banned",
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_core/test_ip_security_banned_ip_events.py tests/test_core/test_ip_security_edge_cases.py -v`
Expected: all PASS (edge-case tests patch `log_activity`/`ip_ban_manager` and don't assert call counts on the event bus for the ban path; if any asserts `send_middleware_event` was NOT called for a banned IP, that assertion encodes the old gap — update it to expect the new event and note it in the task report).

- [ ] **Step 5: Sync mirror + gates**

Run: `make sync && make check-sync && make local-test`
Expected: PASS, coverage 100%.
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core`
Expected: clean.

- [ ] **Step 6: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Fixed`:

```markdown
- Blocking a banned IP now emits an `ip_blocked` event (`filter_type="banned"`); repeat requests from banned IPs were previously invisible to telemetry.
```

```bash
git add guard_core/core/checks/implementations/ip_security.py tests/test_core/test_ip_security_banned_ip_events.py CHANGELOG.md guard_core/sync tests/test_sync
```

Report commit message: `fix(ip-security): emit ip_blocked event when blocking banned IPs`

---

### Task 3: Enforce global IP/country rules on decorated routes (security fix) and set `is_whitelisted` on all branches

**Files:**
- Modify: `guard_core/utils.py:468-493` (`is_ip_allowed`)
- Modify: `guard_core/core/checks/implementations/ip_security.py` (imports, `_check_global_ip_restrictions`, `check`)
- Modify: `CHANGELOG.md`
- Test: `tests/test_core/test_ip_security_global_route_merge.py` (create)
- Possibly update: existing tests that encode the old exclusive-branch behavior (see Step 6)

**Interfaces:**
- Consumes: `is_ip_in_whitelist` from `guard_core.core.checks.helpers` (helpers.py:17), `RouteConfig` fields `ip_whitelist`/`ip_blacklist`/`blocked_countries`/`whitelist_countries`.
- Produces: `is_ip_allowed(ip, config, geo_ip_handler=None, *, skip_ip_lists=False, skip_countries=False) -> bool` — keyword-only additions, existing positional callers unaffected. New semantics: a route's `RouteConfig` overrides ONLY the aspects it sets (IP lists / country rules); unset aspects fall through to global config. `request.state.is_whitelisted` is True when the applicable whitelist (route or global) explicitly matched.

**Semantics being fixed (spec §3.4 defects 1 and 8):** today `check()` returns after route checks whenever `route_config` exists (`ip_security.py:142-147`), so a route decorated with only `@rate_limit(...)` skips the global blacklist entirely, and `is_whitelisted` is only ever set in the global branch.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_core/test_ip_security_global_route_merge.py`:

```python
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.passive_mode = False
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


@pytest.fixture
def ip_security_check(mock_middleware: Mock) -> IpSecurityCheck:
    return IpSecurityCheck(mock_middleware)


def _request_for(route_config: RouteConfig | None) -> Mock:
    request = Mock()
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = route_config
    return request


def _unbanned() -> Any:
    mgr = patch(
        "guard_core.core.checks.implementations.ip_security.ip_ban_manager"
    ).start()
    mgr.is_ip_banned = AsyncMock(return_value=False)
    return mgr


@pytest.fixture(autouse=True)
def _patches() -> Any:
    _unbanned()
    patch("guard_core.core.checks.implementations.ip_security.log_activity").start()
    yield
    patch.stopall()


async def test_decorated_route_still_enforces_global_blacklist(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.blacklist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.rate_limit = 5

    result = await ip_security_check.check(_request_for(route_config))

    assert result is not None
    event_call = cast(
        Any, ip_security_check.middleware
    ).event_bus.send_middleware_event.await_args
    assert event_call.kwargs["event_type"] == "ip_blocked"


async def test_route_ip_whitelist_overrides_global_blacklist(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.blacklist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is True


async def test_route_country_rules_keep_global_ip_blacklist_active(
    ip_security_check: IpSecurityCheck,
    security_config: SecurityConfig,
    mock_middleware: Mock,
) -> None:
    security_config.blacklist = ["1.2.3.4"]
    mock_middleware.geo_ip_handler = Mock()
    mock_middleware.geo_ip_handler.get_country = Mock(return_value="US")
    route_config = RouteConfig()
    route_config.blocked_countries = ["RU"]

    result = await ip_security_check.check(_request_for(route_config))

    assert result is not None


async def test_route_without_ip_fields_leaves_global_whitelist_semantics(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["9.9.9.9"]
    route_config = RouteConfig()
    route_config.rate_limit = 5
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is not None
    assert request.state.is_whitelisted is False


async def test_global_whitelist_match_sets_is_whitelisted_with_route_config(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    security_config.whitelist = ["1.2.3.4"]
    route_config = RouteConfig()
    route_config.rate_limit = 5
    request = _request_for(route_config)

    result = await ip_security_check.check(request)

    assert result is None
    assert request.state.is_whitelisted is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_core/test_ip_security_global_route_merge.py -v`
Expected: `test_decorated_route_still_enforces_global_blacklist`, `test_route_country_rules_keep_global_ip_blacklist_active`, `test_route_without_ip_fields_leaves_global_whitelist_semantics`, and `test_global_whitelist_match_sets_is_whitelisted_with_route_config` FAIL (route branch returns early today). `test_route_ip_whitelist_overrides_global_blacklist` may pass by accident of the old bug — that's fine.

- [ ] **Step 3: Extend `is_ip_allowed` with aspect skips**

In `guard_core/utils.py`, replace the `is_ip_allowed` function (lines 468-493) with:

```python
async def is_ip_allowed(
    ip: str,
    config: Any,
    geo_ip_handler: GeoIPHandler | None = None,
    *,
    skip_ip_lists: bool = False,
    skip_countries: bool = False,
) -> bool:
    try:
        ip_addr = ip_address(ip)

        if not skip_ip_lists:
            if config.whitelist:
                if not await _check_whitelist(ip_addr, ip, config):
                    return False
            elif not await _check_blacklist(ip_addr, ip, config):
                return False

        if not skip_countries and not await _check_blocked_countries(
            ip, config, geo_ip_handler
        ):
            return False

        if not await _check_cloud_providers(ip, config):
            return False

        return True
    except ValueError:
        return False
    except Exception as e:
        logging.error(f"Error checking IP {ip}: {str(e)}")
        return True
```

- [ ] **Step 4: Rework `IpSecurityCheck`**

In `guard_core/core/checks/implementations/ip_security.py`:

Replace the imports at lines 1-11 with:

```python
from ipaddress import ip_address

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.helpers import check_route_ip_access, is_ip_in_whitelist
from guard_core.core.events.event_types import (
    EVENT_DECORATOR_VIOLATION,
    EVENT_IP_BLOCKED,
)
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.utils import is_ip_allowed, log_activity


def _route_whitelist_matches(client_ip: str, route_config: RouteConfig | None) -> bool:
    if not route_config or not route_config.ip_whitelist:
        return False
    try:
        return bool(
            is_ip_in_whitelist(
                client_ip, ip_address(client_ip), route_config.ip_whitelist
            )
        )
    except ValueError:
        return False
```

Replace `_check_global_ip_restrictions` (lines 87-127) with:

```python
    async def _check_global_ip_restrictions(
        self,
        request: GuardRequest,
        client_ip: str,
        route_config: RouteConfig | None = None,
    ) -> GuardResponse | None:
        skip_ip_lists = bool(
            route_config and (route_config.ip_whitelist or route_config.ip_blacklist)
        )
        skip_countries = bool(
            route_config
            and (route_config.blocked_countries or route_config.whitelist_countries)
        )

        is_allowed = await is_ip_allowed(
            client_ip,
            self.config,
            self.middleware.geo_ip_handler,
            skip_ip_lists=skip_ip_lists,
            skip_countries=skip_countries,
        )

        request.state.is_whitelisted = _route_whitelist_matches(
            client_ip, route_config
        ) or (is_allowed and bool(self.config.whitelist) and not skip_ip_lists)

        if is_allowed:
            return None

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
            check_name=self.check_name,
            muted_check_logs=self.config.muted_check_logs,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type=EVENT_IP_BLOCKED,
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"IP {client_ip} not in global allowlist/blocklist",
            ip_address=client_ip,
            filter_type="global",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=403,
                default_message="Forbidden",
            )

        return None
```

Replace `check` (lines 129-147) with:

```python
    async def check(self, request: GuardRequest) -> GuardResponse | None:
        client_ip = getattr(request.state, "client_ip", None)
        route_config = getattr(request.state, "route_config", None)
        if not client_ip:
            return None

        ban_response = await self._check_banned_ip(request, client_ip, route_config)
        if ban_response:
            return ban_response

        if self.middleware.route_resolver.should_bypass_check("ip", route_config):
            return None

        if route_config:
            route_response = await self._check_route_ip_restrictions(
                request, client_ip, route_config
            )
            if route_response:
                return route_response

        return await self._check_global_ip_restrictions(
            request, client_ip, route_config
        )
```

(`_check_banned_ip` and `_check_route_ip_restrictions` bodies are unchanged from Task 2's state.)

- [ ] **Step 5: Run the new tests**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_core/test_ip_security_global_route_merge.py -v`
Expected: all 5 PASS.

- [ ] **Step 6: Run the affected suites and reconcile old-behavior tests**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/ -q --ignore=tests/attack_simulation --ignore=tests/test_sync -x`

Any failing test that asserts a decorated route SKIPS global lists (or that `is_whitelisted` stays unset when a route config exists) encodes the bug being fixed. For each: update the assertion to the new semantics and list every such change in the task report. Do NOT weaken tests unrelated to route/global IP merging — investigate any other failure as a regression in Step 4's code.

- [ ] **Step 7: Sync mirror + full gates**

Run: `make sync && make check-sync && make local-test`
Expected: PASS, coverage 100% (check `guard_core/utils.py` and `ip_security.py` lines in the coverage report — every new branch must be hit; add targeted tests to `tests/test_core/test_ip_security_global_route_merge.py` if any branch is missed, e.g. invalid `client_ip` for `_route_whitelist_matches`' `ValueError` branch:

```python
async def test_route_whitelist_with_unparseable_ip_is_not_whitelisted(
    ip_security_check: IpSecurityCheck, security_config: SecurityConfig
) -> None:
    route_config = RouteConfig()
    route_config.ip_whitelist = ["1.2.3.4"]
    request = _request_for(route_config)
    request.state.client_ip = "not-an-ip"

    result = await ip_security_check.check(request)

    assert request.state.is_whitelisted is False
    assert result is not None
```

note: `check_route_ip_access` returns False for unparseable IPs (helpers.py:85-86), so the route step blocks first — keep the assertion on `result` consistent with what you observe and verify it's the route-block path via the `EVENT_DECORATOR_VIOLATION` event if needed).
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core`
Expected: clean.

- [ ] **Step 8: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Fixed` (and `### Security` if the section convention exists in this CHANGELOG — check the file):

```markdown
- Global IP whitelist/blacklist and country rules are now enforced on routes that carry per-route decorator config. Previously, any decorated route (for example one using only `@rate_limit`) silently skipped every global IP and country rule; per-route settings now override only the aspects they configure (IP lists, country rules) and everything else falls through to the global config.
- `request.state.is_whitelisted` is now populated on decorated routes, so whitelist short-circuits in downstream checks work there too.
```

```bash
git add guard_core/utils.py guard_core/core/checks/implementations/ip_security.py tests/test_core/test_ip_security_global_route_merge.py CHANGELOG.md guard_core/sync tests/test_sync
```

(Include any reconciled test files from Step 6 in the `git add`.)

Report commit message: `fix(ip-security): enforce global IP and country rules on decorated routes`

---

### Task 4: Wire `geo_ip_db_max_age` into the auto-constructed `IPInfoManager`

**Files:**
- Modify: `guard_core/models.py:671-674`
- Modify: `CHANGELOG.md`
- Test: `tests/test_models/test_geo_ip_db_max_age_wiring.py` (create)

**Interfaces:**
- Consumes: `IPInfoManager.__new__(token, db_path=None, max_age=86400)` (`guard_core/handlers/ipinfo_handler.py:28-51`; every construction updates `_max_age`, line 50, so the singleton picks up the new value deterministically).
- Produces: no new API; `SecurityConfig(geo_ip_db_max_age=...)` now has runtime effect.

- [ ] **Step 1: Write the failing test**

```python
from typing import Any, cast

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def _reset_ipinfo_singleton() -> Any:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def test_geo_ip_db_max_age_reaches_auto_constructed_handler() -> None:
    with pytest.warns(DeprecationWarning):
        config = SecurityConfig(
            ipinfo_token="token123",
            blocked_countries=["CN"],
            geo_ip_db_max_age=7200,
        )
    assert cast(Any, config.geo_ip_handler)._max_age == 7200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_models/test_geo_ip_db_max_age_wiring.py -v`
Expected: FAIL with `assert 86400 == 7200`.

- [ ] **Step 3: Implement**

In `guard_core/models.py`, `validate_geo_ip_handler_exists` (line 671), replace:

```python
                self.geo_ip_handler = IPInfoManager(
                    token=self.ipinfo_token,
                    db_path=self.ipinfo_db_path,
                )
```

with:

```python
                self.geo_ip_handler = IPInfoManager(
                    token=self.ipinfo_token,
                    db_path=self.ipinfo_db_path,
                    max_age=self.geo_ip_db_max_age,
                )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_models/test_geo_ip_db_max_age_wiring.py -v`
Expected: PASS

- [ ] **Step 5: Sync mirror + gates**

`models.py` is excluded from unasync (`scripts/unasync.py` SKIP_SRC), but the new test file gets mirrored:
Run: `make sync && make check-sync && make local-test`
Expected: PASS, coverage 100%.
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core`
Expected: clean.

- [ ] **Step 6: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Fixed`:

```markdown
- `geo_ip_db_max_age` is now passed to the auto-constructed IPInfo handler; the setting previously had no runtime effect.
```

```bash
git add guard_core/models.py tests/test_models/test_geo_ip_db_max_age_wiring.py CHANGELOG.md tests/test_sync
```

Report commit message: `fix(geo): honor geo_ip_db_max_age when auto-constructing the IPInfo handler`

---

### Task 5: Remove dead `RouteConfig.session_limits`

**Files:**
- Modify: `guard_core/decorators/base.py:39`
- Modify: `tests/test_decorators/test_base.py:38`
- Modify: `CHANGELOG.md`
- Check: `grep -rn "session_limits" docs/ guard_core/ tests/ --include="*.py" --include="*.md"` — update any doc hit

**Interfaces:**
- Produces: `RouteConfig` no longer has `session_limits`. Nothing in the ecosystem reads or writes it (verified: only its own declaration, its sync mirror, and one default-value test).

- [ ] **Step 1: Delete the attribute**

In `guard_core/decorators/base.py`, delete line 39:

```python
        self.session_limits: dict[str, int] | None = None
```

- [ ] **Step 2: Update the default-values test**

In `tests/test_decorators/test_base.py`, delete line 38:

```python
    assert config.session_limits is None
```

- [ ] **Step 3: Check docs and adapter references**

Run: `grep -rn "session_limits" docs/ CHANGELOG.md 2>/dev/null; grep -rn "session_limits" /Users/renzof/Documents/GitHub/ZZZ/fastapi-guard --include="*.py" --include="*.md" | grep -v ".venv"`
Expected: no hits (if docs hits appear, remove the references in the same task).

- [ ] **Step 4: Sync mirror + gates**

Run: `make sync && make check-sync && make local-test`
Expected: PASS (the generated `guard_core/sync/decorators/base.py` and `tests/test_sync/test_decorators/test_base.py` lose the line automatically), coverage 100%.
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core && make vulture`
Expected: clean.

- [ ] **Step 5: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Removed`:

```markdown
- Dead `RouteConfig.session_limits` attribute (never set by any decorator, never read by any check).
```

```bash
git add guard_core/decorators/base.py tests/test_decorators/test_base.py CHANGELOG.md guard_core/sync tests/test_sync
```

Report commit message: `refactor(decorators): remove dead RouteConfig.session_limits`

---

### Task 6: Shared regex executor + built-in patterns bypass the per-match timeout wrapper

**Files:**
- Modify: `guard_core/detection_engine/compiler.py`
- Modify: `guard_core/handlers/suspatterns_handler.py:555-635`
- Modify: `CHANGELOG.md`
- Test: `tests/test_detection_engine/test_shared_regex_executor.py` (create; if `tests/test_detection_engine/` doesn't exist, check where `tests/test_compiler_cache.py` lives and place the file alongside it as `tests/test_shared_regex_executor.py` instead — mirror the repo's flat-vs-nested convention)

**Interfaces:**
- Produces: `shared_regex_executor() -> concurrent.futures.ThreadPoolExecutor` (module-level, lazy, in `guard_core.detection_engine.compiler`). `PatternCompiler.create_safe_matcher(pattern, timeout=None)` signature unchanged, now submits to the shared executor. `SusPatternsManager._check_regex_pattern` runs built-in categories (`category != "custom"`) via direct `pattern.search(content)`; custom patterns keep the timeout wrapper.
- Rationale (spec §3.4 defect 7, §4.9): today EVERY regex match constructs a `ThreadPoolExecutor(max_workers=1)` (compiler.py:118, suspatterns_handler.py:611-612), and the `with` block's shutdown waits for the running search anyway, making the "timeout" mostly illusory while paying thread-spawn cost per pattern × per content piece.

- [ ] **Step 1: Write the failing tests**

```python
import re
import time
from typing import Any

import pytest

from guard_core.detection_engine.compiler import (
    PatternCompiler,
    shared_regex_executor,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


def test_shared_regex_executor_is_a_singleton() -> None:
    assert shared_regex_executor() is shared_regex_executor()


def test_safe_matcher_times_out_on_catastrophic_pattern() -> None:
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher(r"(a+)+$", timeout=0.05)
    assert matcher("a" * 24 + "b") is None


def test_safe_matcher_still_works_after_a_timeout() -> None:
    compiler = PatternCompiler()
    slow = compiler.create_safe_matcher(r"(a+)+$", timeout=0.05)
    slow("a" * 24 + "b")
    fast = compiler.create_safe_matcher(r"abc")
    assert fast("xxabcxx") is not None


@pytest.fixture
def fresh_manager() -> Any:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    yield manager
    SusPatternsManager._instance = None


async def test_builtin_category_skips_safe_matcher(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("safe matcher used for built-in pattern")

    monkeypatch.setattr(fresh_manager._compiler, "create_safe_matcher", _fail)
    pattern = re.compile(r"<script", re.IGNORECASE)

    threat, timed_out = await fresh_manager._check_regex_pattern(
        pattern, "<script>alert(1)</script>", "1.2.3.4", time.time(), "xss"
    )

    assert threat is not None
    assert timed_out is False


async def test_custom_category_keeps_timeout_wrapper(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = fresh_manager._compiler.create_safe_matcher

    def _tracking(pattern: str, timeout: float | None = None) -> Any:
        calls.append(pattern)
        return real(pattern, timeout)

    monkeypatch.setattr(fresh_manager._compiler, "create_safe_matcher", _tracking)
    pattern = re.compile(r"evil")

    threat, _ = await fresh_manager._check_regex_pattern(
        pattern, "so evil", "1.2.3.4", time.time(), "custom"
    )

    assert threat is not None
    assert calls == ["evil"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_detection_engine/test_shared_regex_executor.py -v` (adjust path per Step 1 placement)
Expected: `ImportError: cannot import name 'shared_regex_executor'` — plus `test_builtin_category_skips_safe_matcher` FAILS once the import exists (current code calls `create_safe_matcher` for every category).

- [ ] **Step 3: Implement the shared executor in `compiler.py`**

Replace the imports (lines 1-4) with:

```python
import asyncio
import concurrent.futures
import re
import time
from collections.abc import Callable
```

After the imports (before `class TimeoutError`), add:

```python
_shared_executor: concurrent.futures.ThreadPoolExecutor | None = None


def shared_regex_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _shared_executor
    if _shared_executor is None:
        _shared_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="guard-regex"
        )
    return _shared_executor
```

In `validate_pattern_safety`, replace the per-test-string executor block (lines 74-100 region) so the loop body reads:

```python
        try:
            compiled = self.compile_pattern_sync(pattern)

            for test_str in test_strings:
                start_time = time.time()

                def _search(text: str = test_str) -> re.Match | None:
                    return compiled.search(text)

                future = shared_regex_executor().submit(_search)
                try:
                    future.result(timeout=0.1)
                except concurrent.futures.TimeoutError:
                    return (
                        False,
                        f"Pattern timed out on test string of length "
                        f"{len(test_str)}",
                    )

                elapsed = time.time() - start_time
                if elapsed > 0.05:
                    return (
                        False,
                        f"Pattern timed out on test string of length {len(test_str)}",
                    )
        except Exception as e:
            return False, f"Pattern validation failed: {str(e)}"
```

(also delete the now-dead `import concurrent.futures` inline line that was at line 76).

Replace `create_safe_matcher` (lines 106-128) with:

```python
    def create_safe_matcher(
        self, pattern: str, timeout: float | None = None
    ) -> Callable[[str], re.Match | None]:
        compiled = self.compile_pattern_sync(pattern)
        match_timeout = timeout or self.default_timeout

        def safe_match(text: str) -> re.Match | None:
            future = shared_regex_executor().submit(compiled.search, text)
            try:
                return future.result(timeout=match_timeout)
            except concurrent.futures.TimeoutError:
                future.cancel()
                return None
            except Exception:
                return None

        return safe_match
```

- [ ] **Step 4: Implement the vetted fast path in `suspatterns_handler.py`**

Add `import concurrent.futures` to the file's top import block.

Replace `_check_regex_pattern` (lines 555-601) with:

```python
    async def _check_regex_pattern(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
    ) -> tuple[dict | None, bool]:
        timeout_occurred = False

        if self._compiler:
            if category == "custom":
                safe_matcher = self._compiler.create_safe_matcher(pattern.pattern)
                match = safe_matcher(content)
                if match is None and time.time() - pattern_start >= 0.9 * 2.0:
                    timeout_occurred = True
                    import logging

                    logging.getLogger("guard_core.handlers.suspatterns").warning(
                        f"Pattern timeout: {pattern.pattern[:50]}..."
                    )
            else:
                match = pattern.search(content)

            if match:
                return {
                    "type": "regex",
                    "pattern": pattern.pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "execution_time": time.time() - pattern_start,
                    "category": category,
                    "weight": _resolve_pattern_weight(pattern.pattern, category),
                }, timeout_occurred
        else:
            match, timeout_occurred = await self._check_pattern_with_timeout(
                pattern, content, ip_address, pattern_start
            )
            if match:
                return {
                    "type": "regex",
                    "pattern": pattern.pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "execution_time": time.time() - pattern_start,
                    "category": category,
                    "weight": _resolve_pattern_weight(pattern.pattern, category),
                }, timeout_occurred

        return None, timeout_occurred
```

Replace `_check_pattern_with_timeout` (lines 603-635) with:

```python
    async def _check_pattern_with_timeout(
        self, pattern: re.Pattern, content: str, ip_address: str, pattern_start: float
    ) -> tuple[re.Match | None, bool]:
        from guard_core.detection_engine.compiler import shared_regex_executor

        future = shared_regex_executor().submit(pattern.search, content)
        try:
            match = future.result(timeout=2.0)
            return match, False
        except concurrent.futures.TimeoutError:
            import logging

            logger = logging.getLogger("guard_core.handlers.suspatterns")
            logger.warning(
                f"Regex timeout exceeded for pattern: "
                f"{pattern.pattern[:50]}... "
                f"Potential ReDoS attack blocked. IP: {ip_address}"
            )
            future.cancel()
            return None, True
        except Exception as e:
            import logging

            logger = logging.getLogger("guard_core.handlers.suspatterns")
            logger.error(
                f"Error in regex search for pattern {pattern.pattern[:50]}...: {e}"
            )
            return None, False
```

(remove the old inline `import concurrent.futures` that was at line 606; keep the inline `import logging` pattern the file already uses).

- [ ] **Step 5: Run the new tests**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_detection_engine/test_shared_regex_executor.py tests/test_compiler_cache.py -v` (adjust path)
Expected: all PASS.

- [ ] **Step 6: Detection regression gates**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/attack_simulation/ -q`
Expected: PASS — detection_rate/fp_rate within baseline tolerance (this is the proof the fast path changed performance, not behavior).
Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/ -q --ignore=tests/test_sync`
Expected: PASS. Existing timeout-path tests may patch `ThreadPoolExecutor` construction — if any fail because the executor is no longer constructed per match, update them to target `shared_regex_executor()` and list the changes in the task report.

- [ ] **Step 7: Sync mirror + full gates**

Run: `make sync && make check-sync && make local-test`
Expected: PASS, coverage 100% on `compiler.py` and `suspatterns_handler.py` touched ranges.
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core`
Expected: clean.
Note: the sync mirror of `compiler.py`/`suspatterns_handler.py` is generated; if `make check-sync` flags `POST_FIXUPS` drift (unasync.py keys fixups to exact method bodies in some handlers), inspect `scripts/unasync.py` FIXUP tables for entries matching the old method text and update those entries to the new text — that is source-maintained, not a hand-edit of generated files.

- [ ] **Step 8: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Changed`:

```markdown
- Detection regex matching now uses one shared worker pool instead of constructing a thread pool per pattern match, and built-in (compile-time-vetted) patterns match directly without the timeout wrapper. Custom patterns keep the ReDoS timeout guard. Substantially reduces per-request detection overhead; detection results are unchanged (attack-simulation baseline holds).
```

```bash
git add guard_core/detection_engine/compiler.py guard_core/handlers/suspatterns_handler.py tests/ CHANGELOG.md guard_core/sync scripts/unasync.py
```

(`scripts/unasync.py` only if Step 7 required fixup updates; `tests/` covers the new test file plus any reconciled timeout tests and generated `tests/test_sync` updates.)

Report commit message: `perf(detection): shared regex executor; vetted built-in patterns bypass per-match timeout wrapper`

---

### Task 7: `build_default_pipeline()` factory in guard-core (Phase 1a)

**Files:**
- Create: `guard_core/core/checks/factory.py`
- Modify: `guard_core/core/checks/__init__.py`
- Modify: `CHANGELOG.md`
- Test: `tests/test_core/test_pipeline_factory.py` (create)

**Interfaces:**
- Produces: `build_default_pipeline(middleware: Any) -> SecurityCheckPipeline` and `DEFAULT_CHECK_CLASSES: tuple[type[SecurityCheck], ...]`, exported from `guard_core.core.checks`. Order is EXACTLY the canonical 17-check order currently hand-listed in fastapi-guard `guard/middleware.py:266-284`. Task 8 consumes this.

- [ ] **Step 1: Write the failing test**

```python
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks import build_default_pipeline


@pytest.fixture
def mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.fail_secure = False
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=500))
    return middleware


def test_default_pipeline_contains_all_checks_in_canonical_order(
    mock_middleware: Mock,
) -> None:
    pipeline = build_default_pipeline(mock_middleware)
    assert pipeline.get_check_names() == [
        "route_config",
        "emergency_mode",
        "https_enforcement",
        "request_logging",
        "request_size_content",
        "required_headers",
        "authentication",
        "referrer",
        "custom_validators",
        "time_window",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
        "rate_limit",
        "suspicious_activity",
        "custom_request",
    ]


def test_default_pipeline_builds_fresh_check_instances_per_call(
    mock_middleware: Mock,
) -> None:
    first = build_default_pipeline(mock_middleware)
    second = build_default_pipeline(mock_middleware)
    assert first.checks[0] is not second.checks[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_core/test_pipeline_factory.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_default_pipeline'`.

- [ ] **Step 3: Create `guard_core/core/checks/factory.py`**

```python
from typing import Any

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations import (
    AuthenticationCheck,
    CloudIpRefreshCheck,
    CloudProviderCheck,
    CustomRequestCheck,
    CustomValidatorsCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    IpSecurityCheck,
    RateLimitCheck,
    ReferrerCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    RequiredHeadersCheck,
    RouteConfigCheck,
    SuspiciousActivityCheck,
    TimeWindowCheck,
    UserAgentCheck,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline

DEFAULT_CHECK_CLASSES: tuple[type[SecurityCheck], ...] = (
    RouteConfigCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    RequiredHeadersCheck,
    AuthenticationCheck,
    ReferrerCheck,
    CustomValidatorsCheck,
    TimeWindowCheck,
    CloudIpRefreshCheck,
    IpSecurityCheck,
    CloudProviderCheck,
    UserAgentCheck,
    RateLimitCheck,
    SuspiciousActivityCheck,
    CustomRequestCheck,
)


def build_default_pipeline(middleware: Any) -> SecurityCheckPipeline:
    return SecurityCheckPipeline([cls(middleware) for cls in DEFAULT_CHECK_CLASSES])
```

- [ ] **Step 4: Export from `guard_core/core/checks/__init__.py`**

Add after the existing imports (line 21):

```python
from guard_core.core.checks.factory import DEFAULT_CHECK_CLASSES, build_default_pipeline
```

and add to `__all__` (keep the list's existing grouping, appending after `"SecurityCheckPipeline",`):

```python
    "DEFAULT_CHECK_CLASSES",
    "build_default_pipeline",
```

- [ ] **Step 5: Run test to verify it passes**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/test_core/test_pipeline_factory.py -v`
Expected: PASS

- [ ] **Step 6: Sync mirror + gates**

Run: `make sync && make check-sync && make local-test`
Expected: PASS, coverage 100% (factory.py fully covered by the two tests).
Run: `uv run ruff format guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core && make vulture`
Expected: clean (if vulture flags `build_default_pipeline`/`DEFAULT_CHECK_CLASSES` as unused despite `__all__`, add them to `vulture_whitelist.py` following the file's existing entry style).

- [ ] **Step 7: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Added`:

```markdown
- `guard_core.core.checks.build_default_pipeline(middleware)`: assembles the canonical 17-check pipeline. Framework adapters should use this instead of hand-listing check classes, so new checks ship to every adapter without adapter changes.
```

```bash
git add guard_core/core/checks/factory.py guard_core/core/checks/__init__.py tests/test_core/test_pipeline_factory.py CHANGELOG.md guard_core/sync tests/test_sync vulture_whitelist.py
```

(`vulture_whitelist.py` only if Step 6 required it.)

Report commit message: `feat(checks): add build_default_pipeline factory for the canonical check pipeline`

---

### Task 8: fastapi-guard consumes the factory (Phase 1b)

**Repo:** `/Users/renzof/Documents/GitHub/ZZZ/fastapi-guard` — run all commands from that directory.

**Precondition:** guard-core with Task 7 merged. For local development BEFORE a guard-core release: `uv pip install -e ../guard-core` inside fastapi-guard's venv. NEVER add `[tool.uv.sources]` or any local-path override to fastapi-guard's `pyproject.toml` — that is per-developer config and must not be committed. This task ships publicly only after the next guard-core release; note that in the task report.

**Files:**
- Modify: `guard/middleware.py:244-290`
- Modify: `CHANGELOG.md`
- Test: existing `tests/test_middleware/test_security_middleware.py` (no new test file; the pipeline-shape assertion already exists in guard-core's factory test)

**Interfaces:**
- Consumes: `build_default_pipeline(middleware)` from `guard_core.core.checks` (Task 7). `SecurityCheckPipeline` import at `guard/middleware.py:9` stays (used for type annotations at lines 94, 171, 260).

- [ ] **Step 1: Replace `_build_security_pipeline`**

In `guard/middleware.py`, replace the whole method (lines 244-290) with:

```python
    def _build_security_pipeline(self) -> None:
        from guard_core.core.checks import build_default_pipeline

        pipeline = build_default_pipeline(self)
        self.security_pipeline = pipeline
        self.logger.info(
            f"Security pipeline initialized with {len(pipeline)} "
            f"checks: {pipeline.get_check_names()}"
        )
```

(The 17-class import block and hand-built list at lines 245-284 are deleted. Check line 260's `SecurityCheckPipeline` reference inside the old import — after deletion, confirm the remaining top-level import at line 9 still satisfies every usage: `grep -n "SecurityCheckPipeline" guard/middleware.py`.)

- [ ] **Step 2: Run the adapter suite**

Run: `REDIS_URL=redis://localhost:6379 uv run pytest tests/ -q -x`
Expected: PASS. If any test asserts the pipeline is built via the old import path (patching `guard_core.core.checks.RouteConfigCheck` etc. at the middleware module), update the patch targets to the factory module (`guard_core.core.checks.factory.<CheckClass>`) and list every change in the task report.

- [ ] **Step 3: Quality gates**

Run: `uv run ruff format guard tests && uv run ruff check guard tests && uv run mypy guard`
Expected: clean.
Run the repo's full local gate if defined in its Makefile (`grep -n "local-test\|^test" Makefile` and run the local variant).
Expected: PASS with the repo's coverage settings (`--cov=guard --cov-branch`); coverage on `guard/middleware.py` must remain 100% for the touched method.

- [ ] **Step 4: CHANGELOG + stage + report commit message**

Add under `## [Unreleased]` → `### Changed`:

```markdown
- The security pipeline is now assembled by guard-core's `build_default_pipeline()`. New guard-core checks are picked up automatically; the middleware no longer hand-lists check classes.
```

```bash
git add guard/middleware.py CHANGELOG.md
```

Report commit message: `refactor(middleware): assemble security pipeline via guard-core build_default_pipeline`

---

## Execution order and dependencies

1 → 2 → 3 (Tasks 2 and 3 edit `ip_security.py`; Task 3's code blocks assume Task 2's event emission is present) → 4 → 5 → 6 → 7 → 8 (Task 8 requires Task 7 via local editable install or a guard-core release).

Tasks 1, 4, 5, 6, 7 are mutually independent of 2/3 and could be reordered, but the listed order keeps `make sync` churn linear.

Follow-up outside this plan (spec Phase 1 covers all adapters): flaskapi-guard and djapi-guard get the same one-method change as Task 8, importing the factory from `guard_core.sync.core.checks` (the sync mirror generates it automatically from Task 7's file).

## Verification at the end of the run

From guard-core root:

```bash
make check-sync && make local-test
uv run ruff format --check guard_core tests && uv run ruff check guard_core tests && uv run mypy guard_core
make vulture && make bandit
REDIS_URL=redis://localhost:6379 uv run pytest tests/attack_simulation/ -q
```

All must pass. Then report: files changed per task, commit messages (uncommitted, staged), any test expectations reconciled in Tasks 3/6/8, and the Task 8 release-ordering note.
