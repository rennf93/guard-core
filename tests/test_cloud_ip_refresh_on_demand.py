import ipaddress
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.checks.implementations.cloud_ip_refresh import (
    CloudIpRefreshCheck,
)
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.models import SecurityConfig


async def test_lazy_init_does_not_trigger_sync_refresh_in_check() -> None:
    config = SecurityConfig(lazy_init=True, block_cloud_providers={"AWS"})
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 9999999999
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    cloud_handler.ip_ranges["AWS"] = set()

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=AsyncMock()) as mock_refresh:
        await check.check(MagicMock())
        mock_refresh.assert_not_awaited()
    middleware.refresh_cloud_ip_ranges.assert_not_awaited()


async def test_eager_init_does_not_trigger_on_demand_refresh() -> None:
    config = SecurityConfig(lazy_init=False, block_cloud_providers={"AWS"})
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 9999999999
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    cloud_handler.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=AsyncMock()) as mock_refresh:
        await check.check(MagicMock())
        mock_refresh.assert_not_awaited()
    middleware.refresh_cloud_ip_ranges.assert_not_awaited()


async def test_scheduled_refresh_still_fires_when_interval_elapsed() -> None:
    config = SecurityConfig(
        lazy_init=False,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=60,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    check = CloudIpRefreshCheck(middleware)
    with patch.object(
        cloud_handler, "schedule_refresh", new_callable=AsyncMock
    ) as schedule:
        await check.check(MagicMock())
    schedule.assert_called_once()
    middleware.refresh_cloud_ip_ranges.assert_not_awaited()


async def test_lazy_init_with_empty_block_cloud_returns_immediately() -> None:
    config = SecurityConfig(lazy_init=True, block_cloud_providers=None)
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    check = CloudIpRefreshCheck(middleware)
    with patch.object(cloud_handler, "refresh_async", new=AsyncMock()) as mock_refresh:
        result = await check.check(MagicMock())
        mock_refresh.assert_not_awaited()
    assert result is None
    middleware.refresh_cloud_ip_ranges.assert_not_awaited()


async def test_lazy_init_scheduled_refresh_fires_when_interval_elapsed() -> None:
    config = SecurityConfig(
        lazy_init=True,
        block_cloud_providers={"AWS"},
        cloud_ip_refresh_interval=60,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    check = CloudIpRefreshCheck(middleware)
    with patch.object(
        cloud_handler, "schedule_refresh", new_callable=AsyncMock
    ) as schedule:
        await check.check(MagicMock())
    schedule.assert_called_once()
    middleware.refresh_cloud_ip_ranges.assert_not_awaited()


async def test_handler_initializer_wires_user_supplied_store() -> None:
    from guard_core.core.initialization.handler_initializer import HandlerInitializer
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    custom_store = InMemoryCloudIpStore()
    config = SecurityConfig(
        enable_redis=True,
        lazy_init=False,
        block_cloud_providers={"AWS"},
        cloud_ip_store=custom_store,
    )
    redis_handler = MagicMock()
    redis_handler.initialize = AsyncMock()
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis_handler,
    )

    call_order: list[str] = []

    def _record_set_store(*_args: object, **_kwargs: object) -> None:
        call_order.append("set_store")

    async def _record_initialize_redis(*_args: object, **_kwargs: object) -> None:
        call_order.append("initialize_redis")

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch("guard_core.handlers.suspatterns_handler.sus_patterns_handler") as sus,
    ):
        cloud.initialize_redis = AsyncMock(side_effect=_record_initialize_redis)
        cloud.set_store = MagicMock(side_effect=_record_set_store)
        ipban.initialize_redis = AsyncMock()
        sus.initialize_redis = AsyncMock()
        await initializer.initialize_redis_handlers()
        cloud.set_store.assert_called_once_with(custom_store)
        assert call_order == ["set_store", "initialize_redis"]


async def test_handler_initializer_user_store_wired_before_lazy_task() -> None:
    import asyncio

    from guard_core.core.initialization.handler_initializer import HandlerInitializer
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    custom_store = InMemoryCloudIpStore()
    config = SecurityConfig(
        enable_redis=True,
        lazy_init=True,
        block_cloud_providers={"AWS"},
        cloud_ip_store=custom_store,
    )
    redis_handler = MagicMock()
    redis_handler.initialize = AsyncMock()
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis_handler,
    )

    call_order: list[str] = []

    def _record_set_store(*_args: object, **_kwargs: object) -> None:
        call_order.append("set_store")

    async def _record_initialize_redis(*_args: object, **_kwargs: object) -> None:
        call_order.append("initialize_redis")

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch("guard_core.handlers.suspatterns_handler.sus_patterns_handler") as sus,
    ):
        cloud.initialize_redis = AsyncMock(side_effect=_record_initialize_redis)
        cloud.set_store = MagicMock(side_effect=_record_set_store)
        ipban.initialize_redis = AsyncMock()
        sus.initialize_redis = AsyncMock()
        await initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
        cloud.set_store.assert_called_once_with(custom_store)
        assert call_order == ["set_store", "initialize_redis"]
