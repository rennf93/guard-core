from typing import Any, cast

import pytest

from guard_core.models import SecurityConfig

BOOL_FIELDS = [
    "enable_penetration_detection",
    "enable_ip_banning",
    "enable_rate_limiting",
    "emergency_mode",
    "enable_rate_limit_auto_ban",
]

UNBOUNDED_INT_FIELDS = ["rate_limit", "rate_limit_window"]

POSITIVE_INT_FIELDS = ["auto_ban_threshold", "auto_ban_duration"]

STR_LIST_FIELDS = ["blocked_user_agents", "emergency_whitelist"]


@pytest.mark.parametrize("field_name", BOOL_FIELDS)
def test_bool_field_reassignment_rejects_non_bool(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be a bool"):
        setattr(config, field_name, "true")


@pytest.mark.parametrize("field_name", BOOL_FIELDS)
@pytest.mark.parametrize("value", [True, False])
def test_bool_field_reassignment_accepts_bool(field_name: str, value: bool) -> None:
    config = SecurityConfig()
    setattr(config, field_name, value)
    assert getattr(config, field_name) is value


@pytest.mark.parametrize("field_name", UNBOUNDED_INT_FIELDS)
def test_unbounded_int_field_reassignment_rejects_non_int(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be an int"):
        setattr(config, field_name, "10")


@pytest.mark.parametrize("field_name", UNBOUNDED_INT_FIELDS)
def test_unbounded_int_field_reassignment_rejects_bool(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be an int"):
        setattr(config, field_name, True)


@pytest.mark.parametrize("field_name", UNBOUNDED_INT_FIELDS)
def test_unbounded_int_field_reassignment_accepts_int(field_name: str) -> None:
    config = SecurityConfig()
    setattr(config, field_name, 42)
    assert getattr(config, field_name) == 42


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_rejects_zero(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be >= 1"):
        setattr(config, field_name, 0)


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_rejects_negative(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be >= 1"):
        setattr(config, field_name, -5)


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_rejects_non_int(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be an int"):
        setattr(config, field_name, "5")


@pytest.mark.parametrize("field_name", POSITIVE_INT_FIELDS)
def test_positive_int_field_reassignment_accepts_boundary_value(
    field_name: str,
) -> None:
    config = SecurityConfig()
    setattr(config, field_name, 1)
    assert getattr(config, field_name) == 1


@pytest.mark.parametrize("field_name", STR_LIST_FIELDS)
def test_str_list_field_reassignment_rejects_non_list(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be a list of str"):
        setattr(config, field_name, "not-a-list")


@pytest.mark.parametrize("field_name", STR_LIST_FIELDS)
def test_str_list_field_reassignment_rejects_non_str_element(field_name: str) -> None:
    config = SecurityConfig()
    with pytest.raises(ValueError, match="must be a list of str"):
        setattr(config, field_name, ["ok", 2])


@pytest.mark.parametrize("field_name", STR_LIST_FIELDS)
def test_str_list_field_reassignment_accepts_str_list(field_name: str) -> None:
    config = SecurityConfig()
    setattr(config, field_name, ["ok"])
    assert getattr(config, field_name) == ["ok"]


def test_endpoint_rate_limits_reassignment_rejects_non_dict() -> None:
    config = SecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, "nope")
    with pytest.raises(ValueError, match="must be a dict"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_rejects_non_str_key() -> None:
    config = SecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, {1: (5, 60)})
    with pytest.raises(ValueError, match="keys must be str"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_rejects_wrong_tuple_length() -> None:
    config = SecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, {"/api": (5, 60, 1)})
    with pytest.raises(ValueError, match=r"\(int, int\) tuple"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_rejects_non_int_entry() -> None:
    config = SecurityConfig()
    bad_value: dict[str, tuple[int, int]] = cast(Any, {"/api": (5.5, 60)})
    with pytest.raises(ValueError, match=r"\(int, int\) tuple"):
        config.endpoint_rate_limits = bad_value


def test_endpoint_rate_limits_reassignment_accepts_valid_mapping() -> None:
    config = SecurityConfig()
    config.endpoint_rate_limits = {"/api": (5, 60)}
    assert config.endpoint_rate_limits == {"/api": (5, 60)}
