from guard_core.models import SecurityConfig


def test_dynamic_rule_violation_accepted_as_muted_event_type() -> None:
    config = SecurityConfig(muted_event_types={"dynamic_rule_violation"})
    assert "dynamic_rule_violation" in config.muted_event_types
