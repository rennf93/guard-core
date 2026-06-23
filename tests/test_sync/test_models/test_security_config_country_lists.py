import pytest

from guard_core.models import SecurityConfig


def test_blocked_countries_default_is_empty_frozenset() -> None:
    config = SecurityConfig()
    assert config.blocked_countries == frozenset()
    assert isinstance(config.blocked_countries, frozenset)


def test_whitelist_countries_default_is_empty_frozenset() -> None:
    config = SecurityConfig()
    assert config.whitelist_countries == frozenset()
    assert isinstance(config.whitelist_countries, frozenset)


def test_blocked_countries_accepts_list_input(tmp_path) -> None:
    config = SecurityConfig(
        blocked_countries=["us", "FR"],
        ipinfo_token="dummy",
        ipinfo_db_path=tmp_path / "country_asn.mmdb",
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_set_input(tmp_path) -> None:
    config = SecurityConfig(
        blocked_countries={"us", "fr"},
        ipinfo_token="dummy",
        ipinfo_db_path=tmp_path / "country_asn.mmdb",
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_tuple_input(tmp_path) -> None:
    config = SecurityConfig(
        blocked_countries=("us", "fr"),
        ipinfo_token="dummy",
        ipinfo_db_path=tmp_path / "country_asn.mmdb",
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_frozenset_input(tmp_path) -> None:
    config = SecurityConfig(
        blocked_countries=frozenset({"us", "fr"}),
        ipinfo_token="dummy",
        ipinfo_db_path=tmp_path / "country_asn.mmdb",
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_invalid_type_raises() -> None:
    with pytest.raises((ValueError, TypeError)):
        SecurityConfig(blocked_countries={"key": "value"})


def test_blocked_countries_none_coerces_to_empty_frozenset() -> None:
    config = SecurityConfig(blocked_countries=None)
    assert config.blocked_countries == frozenset()
    assert isinstance(config.blocked_countries, frozenset)


def test_whitelist_countries_none_coerces_to_empty_frozenset() -> None:
    config = SecurityConfig(whitelist_countries=None)
    assert config.whitelist_countries == frozenset()
    assert isinstance(config.whitelist_countries, frozenset)


def test_whitelist_countries_normalizes_case(tmp_path) -> None:
    config = SecurityConfig(
        whitelist_countries=["us", "Gb", "DE"],
        ipinfo_token="dummy",
        ipinfo_db_path=tmp_path / "country_asn.mmdb",
    )
    assert config.whitelist_countries == frozenset({"US", "GB", "DE"})
