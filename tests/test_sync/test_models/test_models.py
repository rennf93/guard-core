from typing import Any, cast

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def test_security_config_validation() -> None:
    valid_config = SecurityConfig(
        ipinfo_token="valid_token",
        whitelist=["10.0.0.0/24", "192.168.1.1"],
        blacklist=["203.0.113.0/25"],
    )
    assert valid_config.whitelist == ["10.0.0.0/24", "192.168.1.1"]


def test_invalid_ip_validation() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(
            ipinfo_token="test", whitelist=["invalid.ip"], blacklist=["256.0.0.0"]
        )


def test_cloud_provider_validation() -> None:
    config = SecurityConfig(
        ipinfo_token="test", block_cloud_providers={"AWS", "INVALID"}
    )
    assert config.block_cloud_providers == {"AWS"}


def test_security_config_none_whitelist() -> None:
    config = SecurityConfig(ipinfo_token="test", whitelist=None)
    assert config.whitelist is None


def test_none_cloud_providers() -> None:
    config = SecurityConfig(ipinfo_token="test", block_cloud_providers=None)
    assert config.block_cloud_providers == set()


def test_missing_ipinfo_token() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(whitelist_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"], whitelist_countries=["US"])


class ValidGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return True

    def initialize(self) -> None:
        return

    def initialize_redis(self, redis_handler: Any) -> None:
        return

    def initialize_agent(self, agent_handler: Any) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return None

    def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def test_geo_ip_handler_validation() -> None:
    ipinfo = IPInfoManager(token="test")
    config = SecurityConfig(geo_ip_handler=ipinfo)
    assert config.geo_ip_handler == ipinfo

    valid_instance = ValidGeoIPHandler()
    config = SecurityConfig(geo_ip_handler=valid_instance)
    assert config.geo_ip_handler == valid_instance

    config = SecurityConfig(geo_ip_handler=None)
    assert config.geo_ip_handler is None

    class InvalidGeoIPHandler:
        pass

    invalid_handler = cast(SyncGeoIPHandler, InvalidGeoIPHandler())
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_handler=invalid_handler)


def test_geo_ip_handler_deprecated_fallback() -> None:
    config = SecurityConfig(ipinfo_token="test", whitelist_countries=["US"])
    assert config.geo_ip_handler is not None
    assert type(config.geo_ip_handler).__name__ == "IPInfoManager"


def test_geo_ip_handler_async_methods() -> None:
    handler = ValidGeoIPHandler()

    handler.initialize()
    assert handler.is_initialized is True

    mock_redis = object()
    handler.initialize_redis(mock_redis)

    mock_agent = object()
    handler.initialize_agent(mock_agent)

    result = handler.get_country("192.168.1.1")
    assert result is None


def test_validate_trusted_proxies() -> None:
    config = SecurityConfig(trusted_proxies=["127.0.0.1", "192.168.1.0/24"])
    assert "127.0.0.1" in config.trusted_proxies
    assert "192.168.1.0/24" in config.trusted_proxies

    with pytest.raises(ValueError, match="Invalid proxy IP or CIDR range"):
        SecurityConfig(trusted_proxies=["invalid-ip"])

    config = SecurityConfig(trusted_proxies=[])
    assert config.trusted_proxies == []


def test_validate_proxy_depth() -> None:
    config = SecurityConfig(trusted_proxy_depth=2)
    assert config.trusted_proxy_depth == 2

    with pytest.raises(ValueError, match="trusted_proxy_depth must be at least 1"):
        SecurityConfig(trusted_proxy_depth=0)


def test_muted_event_types_validation_invalid() -> None:
    with pytest.raises(ValueError, match="Unknown event types"):
        SecurityConfig(muted_event_types={"nonexistent_event_type"})


def test_muted_metric_types_validation_invalid() -> None:
    with pytest.raises(ValueError, match="Unknown metric types"):
        SecurityConfig(muted_metric_types={"nonexistent_metric_type"})


def test_muted_event_types_validation_valid() -> None:
    config = SecurityConfig(muted_event_types={"penetration_attempt"})
    assert config.muted_event_types == {"penetration_attempt"}


def test_muted_metric_types_validation_valid() -> None:
    config = SecurityConfig(muted_metric_types={"response_time"})
    assert config.muted_metric_types == {"response_time"}
