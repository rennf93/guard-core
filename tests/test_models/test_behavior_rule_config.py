import pytest

from guard_core.models import BehaviorRuleConfig, SecurityConfig


def test_behavior_rule_config_minimum_fields() -> None:
    rule = BehaviorRuleConfig(rule_type="usage", threshold=10)
    assert rule.rule_type == "usage"
    assert rule.threshold == 10
    assert rule.window == 3600
    assert rule.pattern is None
    assert rule.action == "log"
    assert rule.ban_duration is None
    assert rule.correlate_with_detection is False


def test_behavior_rule_config_accepts_all_fields() -> None:
    rule = BehaviorRuleConfig(
        rule_type="return_pattern",
        threshold=20,
        window=300,
        pattern="status:404",
        action="ban",
        ban_duration=7200,
        correlate_with_detection=True,
    )
    assert rule.rule_type == "return_pattern"
    assert rule.pattern == "status:404"
    assert rule.ban_duration == 7200
    assert rule.correlate_with_detection is True


def test_behavior_rule_config_rejects_invalid_rule_type() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(**{"rule_type": "not_a_type", "threshold": 5})


def test_behavior_rule_config_rejects_invalid_action() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(**{"rule_type": "usage", "threshold": 5, "action": "nuke"})


def test_behavior_rule_config_rejects_non_positive_threshold() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(rule_type="usage", threshold=0)


def test_behavior_rule_config_rejects_non_positive_window() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(rule_type="usage", threshold=1, window=0)


def test_behavior_rule_config_rejects_non_positive_ban_duration() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(rule_type="usage", threshold=1, ban_duration=0)


def test_security_config_global_behavior_rules_default_empty() -> None:
    assert SecurityConfig().global_behavior_rules == []


def test_security_config_accepts_global_rules() -> None:
    config = SecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=20,
                window=300,
                pattern="status:404",
                action="ban",
                ban_duration=3600,
                correlate_with_detection=True,
            )
        ]
    )
    assert len(config.global_behavior_rules) == 1
    assert config.global_behavior_rules[0].pattern == "status:404"
