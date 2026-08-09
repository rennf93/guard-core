from guard_core.models import SecurityConfig


def test_fresh_config_has_zero_revision() -> None:
    config = SecurityConfig()
    assert config.revision == 0


def test_revision_increments_on_field_assignment() -> None:
    config = SecurityConfig()
    config.blocked_user_agents = ["badbot"]
    assert config.revision == 1
    config.rate_limit = 5
    assert config.revision == 2


def test_revision_is_not_a_model_field() -> None:
    assert "_revision" not in SecurityConfig.model_fields
    assert "revision" not in SecurityConfig.model_fields


def test_revision_is_absent_from_model_dump() -> None:
    config = SecurityConfig()
    config.rate_limit = 5
    assert "_revision" not in config.model_dump()
    assert "revision" not in config.model_dump()


def test_revision_does_not_affect_equality() -> None:
    mutated = SecurityConfig()
    mutated.rate_limit = 5
    mutated.rate_limit_window = 30

    fresh = SecurityConfig(rate_limit=5, rate_limit_window=30)

    assert mutated.revision != fresh.revision
    assert mutated == fresh


def test_revision_survives_model_copy() -> None:
    config = SecurityConfig()
    config.rate_limit = 5
    copy = config.model_copy()

    assert copy.revision == config.revision

    copy.rate_limit_window = 30
    assert copy.revision == config.revision + 1
    assert config.revision == 1


def test_directly_assigning_revision_before_any_bump_is_visible() -> None:
    config = SecurityConfig()
    config._revision = 100
    assert config.revision == 100


def test_directly_assigning_revision_after_a_bump_does_not_change_it() -> None:
    config = SecurityConfig()
    config.rate_limit = 5
    assert config.revision == 1

    config._revision = 100
    assert config.revision == 1


def test_independent_configs_have_independent_revisions() -> None:
    first = SecurityConfig()
    second = SecurityConfig()

    first.rate_limit = 5

    assert first.revision == 1
    assert second.revision == 0
