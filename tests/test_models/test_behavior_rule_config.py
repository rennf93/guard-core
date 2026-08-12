import pytest

from guard_core.models import (
    BehaviorRuleConfig,
    SecurityConfig,
    return_pattern_requires_response_body,
)


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("status:200", False),
        ("status:404", False),
        ("json:status==ok", True),
        ("regex:err.*", True),
        ("plain substring", True),
    ],
)
def test_return_pattern_requires_response_body(pattern: str, expected: bool) -> None:
    assert return_pattern_requires_response_body(pattern) is expected


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


def test_behavior_scan_response_body_defaults_false() -> None:
    assert SecurityConfig().behavior_scan_response_body is False


def test_behavior_max_response_body_inspect_bytes_default() -> None:
    assert SecurityConfig().behavior_max_response_body_inspect_bytes == 262144


@pytest.mark.parametrize(
    "pattern",
    ["error", "json:status==ok", "regex:err.*", "not found"],
)
def test_global_body_return_pattern_rejected_when_body_scan_disabled(
    pattern: str,
) -> None:
    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        SecurityConfig(
            global_behavior_rules=[
                BehaviorRuleConfig(
                    rule_type="return_pattern", threshold=5, pattern=pattern
                )
            ]
        )


@pytest.mark.parametrize(
    "pattern",
    ["error", "json:status==ok", "regex:err.*", "not found"],
)
def test_global_body_return_pattern_accepted_when_body_scan_enabled(
    pattern: str,
) -> None:
    config = SecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(rule_type="return_pattern", threshold=5, pattern=pattern)
        ],
    )
    assert config.global_behavior_rules[0].pattern == pattern


def test_global_status_return_pattern_accepted_when_body_scan_disabled() -> None:
    config = SecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=5, pattern="status:404"
            )
        ]
    )
    assert config.global_behavior_rules[0].pattern == "status:404"


def test_global_return_pattern_rule_without_pattern_ignored_by_validator() -> None:
    config = SecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(rule_type="return_pattern", threshold=5),
        ]
    )
    assert config.global_behavior_rules[0].pattern is None


def test_global_usage_rule_ignored_by_body_scan_validator() -> None:
    config = SecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(rule_type="usage", threshold=5),
            BehaviorRuleConfig(rule_type="frequency", threshold=5),
        ]
    )
    assert len(config.global_behavior_rules) == 2
