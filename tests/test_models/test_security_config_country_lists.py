import inspect
import warnings
from pathlib import Path
from typing import cast

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig


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


def _current_lineno() -> int:
    frame = inspect.currentframe()
    assert frame is not None
    caller = frame.f_back
    assert caller is not None
    return caller.f_lineno


def test_shadow_warning_points_at_constructor_call_site(tmp_path: Path) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        line_before = _current_lineno()
        SecurityConfig(
            whitelist_countries=["US", "CA"],
            blocked_countries=["CN", "RU"],
            geo_ip_handler=geo_ip_handler,
        )
        line_after = _current_lineno()

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1
    assert matches[0].filename == __file__
    assert line_before < matches[0].lineno <= line_after


def test_shadow_warning_on_runtime_assignment_points_at_assignment_site(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn2.mmdb")
    config = SecurityConfig(
        whitelist_countries=["CA"],
        geo_ip_handler=geo_ip_handler,
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        expected_lineno = _current_lineno() + 1
        config.blocked_countries = frozenset({"CN"})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1
    assert matches[0].filename == __file__
    assert matches[0].lineno == expected_lineno


def test_reassigning_identical_blocked_countries_value_does_not_rewarn(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn3.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = SecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )
        for _ in range(5):
            config.blocked_countries = frozenset({"CN"})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1


@pytest.mark.parametrize(
    "reassigned_value",
    [["CN"], ("CN",), {"CN"}, frozenset({"CN"})],
    ids=["list", "tuple", "set", "frozenset"],
)
def test_reassigning_identical_blocked_countries_as_list_tuple_set_does_not_rewarn(
    tmp_path: Path,
    reassigned_value: list[str] | tuple[str, ...] | set[str] | frozenset[str],
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn8.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = SecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )
        config.blocked_countries = cast(frozenset[str], reassigned_value)

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 1


def test_reassigning_changed_blocked_countries_value_still_warns(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn4.mmdb")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        config = SecurityConfig(
            whitelist_countries=["US"],
            blocked_countries=["CN"],
            geo_ip_handler=geo_ip_handler,
        )
        config.blocked_countries = frozenset({"RU"})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert len(matches) == 2


def test_raising_bool_on_shadow_check_does_not_mutate_field_or_revision(
    tmp_path: Path,
) -> None:
    class _BoomBool:
        def __bool__(self) -> bool:
            raise RuntimeError("boom")

    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn5.mmdb")
    config = SecurityConfig(
        whitelist_countries=["US"],
        geo_ip_handler=geo_ip_handler,
    )
    original_blocked = config.blocked_countries
    original_revision = config.revision

    with pytest.raises(RuntimeError, match="boom"):
        config.blocked_countries = cast(frozenset[str], _BoomBool())

    assert config.blocked_countries == original_blocked
    assert config.revision == original_revision


def test_raising_bool_with_empty_whitelist_short_circuits_without_raising() -> None:
    class _BoomBool:
        def __bool__(self) -> bool:
            raise RuntimeError("boom")

    config = SecurityConfig()
    boom = _BoomBool()

    config.blocked_countries = cast(frozenset[str], boom)

    assert config.blocked_countries is boom


def test_shadow_dedup_compares_non_collection_new_value_without_crashing(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn7.mmdb")
    config = SecurityConfig(blocked_countries=["CN"], geo_ip_handler=geo_ip_handler)
    non_collection = object()

    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        config.whitelist_countries = cast(frozenset[str], non_collection)

    assert config.whitelist_countries is non_collection


def test_model_copy_update_bypasses_shadow_warning_documented_gap(
    tmp_path: Path,
) -> None:
    geo_ip_handler = IPInfoManager(token="dummy", db_path=tmp_path / "asn6.mmdb")
    base = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=geo_ip_handler)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        shadowed = base.model_copy(update={"blocked_countries": frozenset({"CN"})})

    matches = [w for w in caught if "blocked_countries is ignored" in str(w.message)]
    assert matches == []
    assert shadowed.whitelist_countries and shadowed.blocked_countries
