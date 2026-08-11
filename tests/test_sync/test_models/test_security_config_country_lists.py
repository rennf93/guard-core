import warnings
from pathlib import Path

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager


def test_blocked_countries_default_is_empty_frozenset() -> None:
    config = SecurityConfig()
    assert config.blocked_countries == frozenset()
    assert isinstance(config.blocked_countries, frozenset)


def test_whitelist_countries_default_is_empty_frozenset() -> None:
    config = SecurityConfig()
    assert config.whitelist_countries == frozenset()
    assert isinstance(config.whitelist_countries, frozenset)


def test_blocked_countries_accepts_list_input(tmp_path: Path) -> None:
    config = SecurityConfig(
        blocked_countries=["us", "FR"],
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_set_input(tmp_path: Path) -> None:
    config = SecurityConfig(
        blocked_countries={"us", "fr"},
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_tuple_input(tmp_path: Path) -> None:
    config = SecurityConfig(
        blocked_countries=("us", "fr"),
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.blocked_countries == frozenset({"US", "FR"})


def test_blocked_countries_accepts_frozenset_input(tmp_path: Path) -> None:
    config = SecurityConfig(
        blocked_countries=frozenset({"us", "fr"}),
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
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


def test_whitelist_countries_normalizes_case(tmp_path: Path) -> None:
    config = SecurityConfig(
        whitelist_countries=["us", "Gb", "DE"],
        geo_ip_handler=IPInfoManager(
            token="dummy", db_path=tmp_path / "country_asn.mmdb"
        ),
    )
    assert config.whitelist_countries == frozenset({"US", "GB", "DE"})


def test_both_country_lists_emits_shadow_warning(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        SecurityConfig(
            whitelist_countries=["US", "CA"],
            blocked_countries=["CN", "RU"],
            geo_ip_handler=IPInfoManager(
                token="dummy", db_path=tmp_path / "country_asn.mmdb"
            ),
        )


def test_whitelist_alone_emits_no_shadow_warning(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(
            whitelist_countries=["US", "CA"],
            geo_ip_handler=IPInfoManager(
                token="dummy", db_path=tmp_path / "country_asn.mmdb"
            ),
        )
    assert not any("blocked_countries is ignored" in str(w.message) for w in caught)


def test_blocked_alone_emits_no_shadow_warning(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(
            blocked_countries=["CN", "RU"],
            geo_ip_handler=IPInfoManager(
                token="dummy", db_path=tmp_path / "country_asn.mmdb"
            ),
        )
    assert not any("blocked_countries is ignored" in str(w.message) for w in caught)
