import asyncio
from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


def _rules(**kwargs: object) -> DynamicRules:
    base = {
        "rule_id": "test-rule",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(kwargs)
    return DynamicRules(**base)


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


@pytest.mark.asyncio
async def test_apply_rules_rolls_back_on_partial_failure() -> None:
    config = SecurityConfig()
    config.blocked_countries = ["XX"]
    config.whitelist_countries = ["YY"]
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"], whitelist_countries=["NEW2"])

    with patch.object(
        manager,
        "_apply_blocking_rules",
        AsyncMock(side_effect=RuntimeError("kaboom")),
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            await manager._apply_rules(rules)

    assert config.blocked_countries == ["XX"]
    assert config.whitelist_countries == ["YY"]


@pytest.mark.asyncio
async def test_apply_rules_persists_on_success() -> None:
    config = SecurityConfig()
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])
    await manager._apply_rules(rules)

    assert config.blocked_countries == ["NEW"]


@pytest.mark.asyncio
async def test_concurrent_rule_application_serializes() -> None:
    config = SecurityConfig()
    manager = DynamicRuleManager(config)
    observed: list[list[str]] = []

    original_apply_blocking = manager._apply_blocking_rules

    async def slow_blocking(rules: DynamicRules) -> None:
        observed.append(list(config.blocked_countries))
        await asyncio.sleep(0.05)
        await original_apply_blocking(rules)

    with patch.object(manager, "_apply_blocking_rules", side_effect=slow_blocking):
        rules_a = _rules(blocked_countries=["AA"])
        rules_b = _rules(blocked_countries=["BB"])
        await asyncio.gather(
            manager._apply_rules(rules_a),
            manager._apply_rules(rules_b),
        )

    assert len(observed) == 2
    assert observed[0] in ([], ["AA"], ["BB"])
    assert observed[1] in ([], ["AA"], ["BB"])
    assert observed[0] != observed[1]


@pytest.mark.asyncio
async def test_rollback_restores_all_snapshot_fields() -> None:
    config = SecurityConfig(
        rate_limit=100,
        enable_ip_banning=True,
        emergency_mode=False,
    )
    config.blocked_countries = ["OLD_COUNTRY"]
    manager = DynamicRuleManager(config)

    rules = _rules(
        blocked_countries=["NEW_COUNTRY"],
        global_rate_limit=999,
        enable_ip_banning=False,
    )

    with patch.object(
        manager,
        "_apply_feature_toggles",
        AsyncMock(side_effect=RuntimeError("fail")),
    ):
        with pytest.raises(RuntimeError):
            await manager._apply_rules(rules)

    assert config.blocked_countries == ["OLD_COUNTRY"]
    assert config.rate_limit == 100
    assert config.enable_ip_banning is True
    assert config.emergency_mode is False
