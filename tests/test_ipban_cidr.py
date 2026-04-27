import time
from collections.abc import Generator

import pytest

from guard_core.handlers.ipban_handler import IPBanManager


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.mark.asyncio
async def test_cidr_ban_matches_addresses_in_v4_range() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("10.0.0.0/24", duration=300, reason="cidr_test")

    assert await manager.is_ip_banned("10.0.0.5") is True
    assert await manager.is_ip_banned("10.0.0.255") is True
    assert await manager.is_ip_banned("10.0.1.1") is False


@pytest.mark.asyncio
async def test_cidr_ban_matches_addresses_in_v6_range() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("2001:db8::/32", duration=300, reason="cidr_v6")

    assert await manager.is_ip_banned("2001:db8:1::1") is True
    assert await manager.is_ip_banned("2001:db9::1") is False


@pytest.mark.asyncio
async def test_exact_ip_ban_still_works_alongside_cidr() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("192.168.1.50", duration=300, reason="exact")
    await manager.ban_ip("172.16.0.0/16", duration=300, reason="cidr")

    assert await manager.is_ip_banned("192.168.1.50") is True
    assert await manager.is_ip_banned("172.16.42.99") is True
    assert await manager.is_ip_banned("192.168.1.51") is False


@pytest.mark.asyncio
async def test_invalid_cidr_raises() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    with pytest.raises(ValueError):
        await manager.ban_ip("bad/24", duration=300, reason="bad")


@pytest.mark.asyncio
async def test_invalid_ip_address_in_is_ip_banned_returns_false() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    assert await manager.is_ip_banned("not-an-ip") is False


@pytest.mark.asyncio
async def test_cidr_ban_expiry_pruned_at_check_time() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("10.0.0.0/24", duration=1, reason="short")
    assert await manager.is_ip_banned("10.0.0.5") is True

    time.sleep(1.1)
    assert await manager.is_ip_banned("10.0.0.5") is False


@pytest.mark.asyncio
async def test_cidr_ban_redis_path_stores_network() -> None:
    from unittest.mock import AsyncMock

    manager = IPBanManager()
    manager.redis_handler = AsyncMock()
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("10.0.0.0/24", duration=300, reason="cidr_redis")

    manager.redis_handler.set_key.assert_awaited_once()
    call_args = manager.redis_handler.set_key.call_args
    assert call_args[0][0] == "banned_networks"
    assert "10.0.0.0/24" in call_args[0][1]


@pytest.mark.asyncio
async def test_cidr_ban_redis_failure_falls_back_to_local() -> None:
    from unittest.mock import AsyncMock

    manager = IPBanManager()
    redis_mock = AsyncMock()
    redis_mock.set_key.side_effect = OSError("Redis down")
    manager.redis_handler = redis_mock
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("10.0.0.0/24", duration=300, reason="cidr_fallback")

    assert len(manager.banned_networks) == 1


@pytest.mark.asyncio
async def test_cidr_ban_redis_failure_exceeds_cap_raises() -> None:
    from unittest.mock import AsyncMock

    manager = IPBanManager()
    redis_mock = AsyncMock()
    redis_mock.set_key.side_effect = OSError("Redis down")
    manager.redis_handler = redis_mock
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    with pytest.raises(OSError):
        await manager.ban_ip(
            "10.0.0.0/24",
            duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
            reason="cidr_fallback_cap",
        )


@pytest.mark.asyncio
async def test_invalid_exact_ip_raises() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    with pytest.raises(ValueError, match="Invalid IP address"):
        await manager.ban_ip("not-an-ip-no-slash", duration=300, reason="bad_ip")


@pytest.mark.asyncio
async def test_v4_address_not_in_v6_network() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    await manager.ban_ip("2001:db8::/32", duration=300, reason="v6_only")

    assert await manager.is_ip_banned("10.0.0.1") is False


@pytest.mark.asyncio
async def test_cidr_ban_no_redis_exceeds_cap_raises() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()
    manager.banned_networks.clear()

    with pytest.raises(ValueError, match="exceeds local cache capacity"):
        await manager.ban_ip(
            "10.0.0.0/24",
            duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
            reason="cap_exceeded",
        )
