import pytest

from guard_core.models import SecurityConfig


def test_lazy_init_default_false() -> None:
    assert SecurityConfig().lazy_init is False


def test_lazy_init_accepts_true() -> None:
    assert SecurityConfig(lazy_init=True).lazy_init is True


def test_geo_ip_db_max_age_default_86400() -> None:
    assert SecurityConfig().geo_ip_db_max_age == 86400


def test_geo_ip_db_max_age_accepts_custom() -> None:
    assert SecurityConfig(geo_ip_db_max_age=7200).geo_ip_db_max_age == 7200


def test_geo_ip_db_max_age_rejects_below_3600() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_db_max_age=3599)


def test_geo_ip_db_max_age_rejects_above_604800() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_db_max_age=604801)


def test_cloud_ip_store_default_none() -> None:
    assert SecurityConfig().cloud_ip_store is None


def test_cloud_ip_store_accepts_protocol_instance() -> None:
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    store = InMemoryCloudIpStore()
    assert SecurityConfig(cloud_ip_store=store).cloud_ip_store is store
