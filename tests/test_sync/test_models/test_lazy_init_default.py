from guard_core.models import SecurityConfig


def test_lazy_init_default_is_true() -> None:
    config = SecurityConfig()
    assert config.lazy_init is True


def test_lazy_init_can_be_set_false_explicitly() -> None:
    config = SecurityConfig(lazy_init=False)
    assert config.lazy_init is False
