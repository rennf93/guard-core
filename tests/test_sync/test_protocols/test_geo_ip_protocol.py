import inspect

from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def test_geo_ip_protocol_declares_refresh() -> None:
    assert "refresh" in SyncGeoIPHandler.__dict__ or any(
        "refresh" in c.__dict__ for c in SyncGeoIPHandler.__mro__
    )


def test_geo_ip_protocol_declares_close() -> None:
    assert "close" in SyncGeoIPHandler.__dict__ or any(
        "close" in c.__dict__ for c in SyncGeoIPHandler.__mro__
    )


def test_geo_ip_protocol_close_is_sync() -> None:
    assert not inspect.iscoroutinefunction(SyncGeoIPHandler.close)
