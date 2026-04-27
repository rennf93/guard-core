import threading
import time
from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


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


def test_apply_rules_rolls_back_on_partial_failure() -> None:
    config = SecurityConfig()
    config.blocked_countries = ["XX"]
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])

    with patch.object(
        manager, "_apply_blocking_rules", MagicMock(side_effect=RuntimeError("kaboom"))
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            manager._apply_rules(rules)

    assert config.blocked_countries == ["XX"]


def test_apply_rules_persists_on_success() -> None:
    config = SecurityConfig()
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])
    manager._apply_rules(rules)

    assert config.blocked_countries == ["NEW"]


def test_concurrent_threads_serialize() -> None:
    config = SecurityConfig()
    manager = DynamicRuleManager(config)
    observed: list[list[str]] = []

    original = manager._apply_blocking_rules

    def slow(rules: DynamicRules) -> None:
        observed.append(list(config.blocked_countries))
        time.sleep(0.05)
        original(rules)

    with patch.object(manager, "_apply_blocking_rules", side_effect=slow):
        threads = [
            threading.Thread(
                target=manager._apply_rules,
                args=(_rules(blocked_countries=["AA"]),),
            ),
            threading.Thread(
                target=manager._apply_rules,
                args=(_rules(blocked_countries=["BB"]),),
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    assert len(observed) == 2
    assert observed[0] != observed[1]


def test_rollback_restores_all_snapshot_fields() -> None:
    config = SecurityConfig(
        rate_limit=100,
        enable_ip_banning=True,
    )
    config.blocked_countries = ["OLD"]
    manager = DynamicRuleManager(config)

    rules = _rules(
        blocked_countries=["NEW"],
        global_rate_limit=999,
        enable_ip_banning=False,
    )

    with patch.object(
        manager,
        "_apply_feature_toggles",
        MagicMock(side_effect=RuntimeError("fail")),
    ):
        with pytest.raises(RuntimeError):
            manager._apply_rules(rules)

    assert config.blocked_countries == ["OLD"]
    assert config.rate_limit == 100
    assert config.enable_ip_banning is True
