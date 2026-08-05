from collections.abc import Callable
from importlib.util import find_spec as real_find_spec
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations import (
    CloudIpRefreshCheck,
    CloudProviderCheck,
    IpSecurityCheck,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler


def _blocking_find_spec(*blocked_names: str) -> Callable[..., object]:
    def fake_find_spec(name: str, *args: object, **kwargs: object) -> object:
        if name in blocked_names:
            return None
        return real_find_spec(name, *args, **kwargs)

    return fake_find_spec


def test_default_security_check_requires_is_empty() -> None:
    assert SecurityCheck.requires == ()
    assert IpSecurityCheck.requires == ()


def test_cloud_provider_check_requires_cloud_extra() -> None:
    assert CloudProviderCheck.requires == ("cloud",)


def test_cloud_ip_refresh_check_requires_cloud_extra() -> None:
    assert CloudIpRefreshCheck.requires == ("cloud",)


def test_country_rules_without_maxminddb_raises_named_extra(monkeypatch) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(blocked_countries={"US"})

    assert "pip install guard-core[geo]" in str(exc_info.value)
    assert not isinstance(exc_info.value, ImportError)


def test_ipinfo_token_without_maxminddb_raises_validation_error_not_import_error(
    monkeypatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(ipinfo_token="token123", blocked_countries=["CN"])

    assert "pip install guard-core[geo]" in str(exc_info.value)


def test_custom_geo_ip_handler_without_maxminddb_raises_named_extra(
    monkeypatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))
    handler = MagicMock(spec=GeoIPHandler)

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(geo_ip_handler=handler)

    assert "pip install guard-core[geo]" in str(exc_info.value)


def test_enable_redis_default_without_redis_package_raises_named_extra(
    monkeypatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("redis"))

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig()

    assert "pip install guard-core[redis]" in str(exc_info.value)


def test_enable_redis_false_without_redis_package_does_not_raise(monkeypatch) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("redis"))

    config = SecurityConfig(enable_redis=False)

    assert config.enable_redis is False


def test_block_cloud_providers_without_cloud_packages_raises_named_extra(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "importlib.util.find_spec", _blocking_find_spec("aiohttp", "requests")
    )

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(block_cloud_providers={"AWS"})

    assert "pip install guard-core[cloud]" in str(exc_info.value)


def test_block_cloud_providers_none_without_cloud_packages_does_not_raise(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "importlib.util.find_spec", _blocking_find_spec("aiohttp", "requests")
    )

    config = SecurityConfig(block_cloud_providers=None)

    assert config.block_cloud_providers == set()


def test_block_cloud_providers_with_only_requests_available_does_not_raise(
    monkeypatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("aiohttp"))

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert config.block_cloud_providers == {"AWS"}
