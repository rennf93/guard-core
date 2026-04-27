from collections.abc import Generator

import pytest

from guard_core.sync.handlers.ipban_handler import IPBanManager


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def test_ban_short_duration_succeeds_when_redis_unavailable() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()

    manager.ban_ip("10.0.0.5", duration=300, reason="test")
    assert "10.0.0.5" in manager.banned_ips


def test_ban_at_cap_succeeds_when_redis_unavailable() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()

    manager.ban_ip(
        "10.0.0.6", duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS, reason="test"
    )
    assert "10.0.0.6" in manager.banned_ips


def test_ban_longer_than_cap_raises_when_redis_unavailable() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()

    with pytest.raises(ValueError, match="exceeds local cache capacity"):
        manager.ban_ip(
            "10.0.0.7",
            duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
            reason="test",
        )
    assert "10.0.0.7" not in manager.banned_ips


def test_ban_zero_or_negative_duration_raises() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    with pytest.raises(ValueError):
        manager.ban_ip("10.0.0.8", duration=0, reason="test")

    with pytest.raises(ValueError):
        manager.ban_ip("10.0.0.9", duration=-1, reason="test")


def test_ban_longer_than_cap_succeeds_when_redis_available() -> None:
    from unittest.mock import MagicMock

    manager = IPBanManager()
    manager.redis_handler = MagicMock()
    manager.banned_ips.clear()

    manager.ban_ip(
        "10.0.0.10", duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1, reason="test"
    )
    assert "10.0.0.10" in manager.banned_ips
    manager.redis_handler.set_key.assert_called_once()
