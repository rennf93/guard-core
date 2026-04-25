import inspect

from guard_core.protocols.geo_ip_protocol import GeoIPHandler


def test_geo_ip_protocol_declares_refresh() -> None:
    assert "refresh" in GeoIPHandler.__dict__ or any(
        "refresh" in c.__dict__ for c in GeoIPHandler.__mro__
    )


def test_geo_ip_protocol_refresh_is_async() -> None:  # async-only
    assert inspect.iscoroutinefunction(GeoIPHandler.refresh)


def test_geo_ip_protocol_declares_close() -> None:
    assert "close" in GeoIPHandler.__dict__ or any(
        "close" in c.__dict__ for c in GeoIPHandler.__mro__
    )


def test_geo_ip_protocol_close_is_sync() -> None:
    assert not inspect.iscoroutinefunction(GeoIPHandler.close)
