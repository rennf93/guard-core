import threading
import time
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


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
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        blocked_countries=frozenset({"XX"}),
    )
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])

    with patch.object(
        manager, "_apply_blocking_rules", MagicMock(side_effect=RuntimeError("kaboom"))
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            manager._apply_rules(rules)

    assert config.blocked_countries == frozenset({"XX"})


def test_apply_rules_persists_on_success() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock(spec=SyncGeoIPHandler))
    manager = DynamicRuleManager(config)

    rules = _rules(blocked_countries=["NEW"])
    manager._apply_rules(rules)

    assert config.blocked_countries == frozenset({"NEW"})


def test_concurrent_threads_serialize() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock(spec=SyncGeoIPHandler))
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
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        blocked_countries=frozenset({"OLD"}),
    )
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

    assert config.blocked_countries == frozenset({"OLD"})
    assert config.rate_limit == 100
    assert config.enable_ip_banning is True


def test_rollback_restores_auto_ban_overrides() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        auto_ban_threshold=5,
        auto_ban_duration=3600,
        enable_rate_limit_auto_ban=False,
    )
    manager = DynamicRuleManager(config)

    rules = _rules(
        auto_ban_threshold=7,
        auto_ban_duration=1800,
        enable_rate_limit_auto_ban=True,
        emergency_mode=True,
    )

    with patch.object(
        manager,
        "_activate_emergency_mode",
        MagicMock(side_effect=RuntimeError("fail")),
    ):
        with pytest.raises(RuntimeError, match="fail"):
            manager._apply_rules(rules)

    assert config.auto_ban_threshold == 5
    assert config.auto_ban_duration == 3600
    assert config.enable_rate_limit_auto_ban is False


def test_apply_rules_captures_base_snapshot_on_first_activation() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rules = _rules(auto_ban_threshold=7)
    manager._apply_rules(rules)

    assert manager._active_base_snapshot is not None
    assert manager._active_base_snapshot["auto_ban_threshold"] == 5
    assert config.auto_ban_threshold == 7


def test_apply_rules_retains_base_snapshot_across_superseding_push() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rule_a = _rules(rule_id="rule-a", auto_ban_threshold=7)
    manager._apply_rules(rule_a)
    manager.current_rules = rule_a
    base_snapshot = manager._active_base_snapshot
    assert base_snapshot is not None
    assert base_snapshot["auto_ban_threshold"] == 5

    rule_b = _rules(rule_id="rule-b", auto_ban_threshold=9)
    manager._apply_rules(rule_b)

    assert manager._active_base_snapshot is base_snapshot
    assert manager._active_base_snapshot["auto_ban_threshold"] == 5
    assert config.auto_ban_threshold == 9


def test_check_rule_expiry_reverts_expired_rule_and_clears_state() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rule = _rules(
        auto_ban_threshold=7,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    manager._apply_rules(rule)
    active_rule: DynamicRules | None = rule
    manager.current_rules = active_rule
    assert config.auto_ban_threshold == 7

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert manager._active_base_snapshot is None


def test_check_rule_expiry_noop_for_future_expiry() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    rule = _rules(
        auto_ban_threshold=7,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    manager._apply_rules(rule)
    manager.current_rules = rule

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 7
    assert manager.current_rules == rule


def test_check_rule_expiry_noop_when_no_active_rule() -> None:
    config = SecurityConfig(geo_ip_handler=MagicMock(spec=SyncGeoIPHandler))
    manager = DynamicRuleManager(config)

    manager._check_rule_expiry()

    assert manager.current_rules is None


def test_check_rule_expiry_clears_expired_rule_without_snapshot() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)
    manager.current_rules = _rules(
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
    )

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None


def test_apply_rules_failed_first_apply_leaves_no_stale_base_snapshot() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    with patch.object(
        manager,
        "_apply_feature_toggles",
        MagicMock(side_effect=RuntimeError("kaboom")),
    ):
        with pytest.raises(RuntimeError, match="kaboom"):
            manager._apply_rules(_rules(auto_ban_threshold=7))

    snapshot_after_failure = manager._active_base_snapshot
    assert manager.current_rules is None
    assert snapshot_after_failure is None

    config.auto_ban_threshold = 6

    manager._apply_rules(_rules(rule_id="rule-2", auto_ban_threshold=9))

    base_snapshot = manager._active_base_snapshot
    assert base_snapshot is not None
    assert base_snapshot["auto_ban_threshold"] == 6
    assert config.auto_ban_threshold == 9


def test_check_rule_expiry_naive_past_expiry_reverts_without_typeerror() -> None:
    config = SecurityConfig(
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler), auto_ban_threshold=5
    )
    manager = DynamicRuleManager(config)

    naive_past = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None)
    rule = _rules(auto_ban_threshold=7, expires_at=naive_past)
    manager._apply_rules(rule)
    manager.current_rules = rule
    assert config.auto_ban_threshold == 7

    manager._check_rule_expiry()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
